import CryptoKit
import Foundation

/// Deterministic hash of the semantic bookmark tree, ignoring storage-specific
/// metadata such as Safari `Sync.Data` / `Sync.ServerID`, timestamps, or plist bytes.
enum BookmarkSnapshotFingerprint {
    static func compute(_ nodes: [ParsedBookmark]) -> String {
        let sorted = nodes.sorted {
            let lhsParent = $0.parentId ?? ""
            let rhsParent = $1.parentId ?? ""
            if lhsParent != rhsParent { return lhsParent < rhsParent }
            if $0.index != $1.index { return $0.index < $1.index }
            if $0.id != $1.id { return $0.id < $1.id }
            if $0.title != $1.title { return $0.title < $1.title }
            return ($0.url ?? "") < ($1.url ?? "")
        }

        var hasher = SHA256()
        hashCount(sorted.count, into: &hasher)
        for node in sorted {
            hashString(node.id, into: &hasher)
            hashString(node.title, into: &hasher)
            hashString(node.url ?? "", into: &hasher)
            hashString(node.type == .folder ? "F" : "L", into: &hasher)
            hashString(node.parentId ?? "", into: &hasher)
            hashCount(node.index, into: &hasher)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func hashCount(_ value: Int, into hasher: inout SHA256) {
        var encoded = Int64(value).bigEndian
        withUnsafeBytes(of: &encoded) { hasher.update(bufferPointer: $0) }
    }

    private static func hashString(_ value: String, into hasher: inout SHA256) {
        let utf8 = Data(value.utf8)
        hashCount(utf8.count, into: &hasher)
        hasher.update(data: utf8)
    }
}

/// Summary of CloudKit metadata actions taken while writing Safari's `Bookmarks.plist`.
struct SafariWriteReport: Equatable, Sendable {
    let hasRootSync: Bool
    let didRequestCloudKitMigration: Bool
    let preservedCount: Int
    let invalidatedCount: Int
    let createdCount: Int
    let tombstonedCount: Int
}

/// Abstraction over daemon/preference-cache resets triggered after setting
/// `CloudKitMigrationState = 0` on the live Safari `Bookmarks.plist`.
protocol SafariSyncAgentResetting: Sendable {
    func resetSyncAgents()
}

struct SystemSafariSyncAgentResetter: SafariSyncAgentResetting {
    func resetSyncAgents() {
        // Terminate the sync agent first so it cannot flush cached Sync.Data over
        // our newly written Bookmarks.plist before cfprefsd drops its cache.
        _ = runKillall(processName: "SafariBookmarksSyncAgent")
        Thread.sleep(forTimeInterval: 0.05)
        _ = runKillall(processName: "cfprefsd")
    }

    private func runKillall(processName: String) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/killall")
        process.arguments = ["-TERM", processName]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus
        } catch {
            SyncLog.error("Failed to reset \(processName): \(error.localizedDescription)")
            return -1
        }
    }
}

enum SafariSyncCoordinator {
    static let liveSafariPlistRelativePath = "Library/Safari/Bookmarks.plist"
    static let defaultMigrationResetCooldown: TimeInterval = 20.0
    static let defaultQuiescenceWindow: TimeInterval = 1.5

    /// Returns `true` only for the signed-in user's real Safari `Bookmarks.plist`.
    /// Tests operating on temporary plists must never trigger `killall`.
    static func isLiveSafariPlistPath(
        _ url: URL,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> Bool {
        let candidate = canonicalPath(url)
        let live = canonicalPath(homeDirectory.appendingPathComponent(liveSafariPlistRelativePath))
        return candidate == live
    }

    private static func canonicalPath(_ url: URL) -> String {
        url.standardizedFileURL.resolvingSymlinksInPath().path
    }
}

/// Helper for preserving CloudKit `Sync` state across Safari `Bookmarks.plist` writes.
struct SafariCloudKitTreeHelper {
    private static let ignoredContainerTitles: Set<String> = [
        "History",
        "Deleted by BookmarkSync",
    ]

    let orderByUuid: [String: Int]
    let urlQueues: [String: [String]]
    let folderQueues: [String: [String]]

    init(rootChildren: [[String: Any]]) {
        var orderMap: [String: Int] = [:]
        var urls: [String: [String]] = [:]
        var folders: [String: [String]] = [:]

        func visit(items: [[String: Any]], isRootLevel: Bool) {
            for (index, item) in items.enumerated() {
                let title = SafariParser.nodeTitle(in: item) ?? ""
                if isRootLevel && Self.ignoredContainerTitles.contains(title) {
                    continue
                }
                if title == "Deleted by BookmarkSync" {
                    continue
                }

                let uuid = item["WebBookmarkUUID"] as? String
                if let uuid {
                    orderMap[uuid] = index
                }

                let type = item["WebBookmarkType"] as? String
                if type == "WebBookmarkTypeList" {
                    if !isRootLevel, let uuid, !title.isEmpty {
                        folders[title, default: []].append(uuid)
                    } else if isRootLevel && !["BookmarksBar", "BookmarksMenu", "ReadingList", "Reading List", "com.apple.ReadingList"].contains(title),
                              let uuid, !title.isEmpty {
                        folders[title, default: []].append(uuid)
                    }
                    if let sub = item["Children"] as? [[String: Any]] {
                        visit(items: sub, isRootLevel: false)
                    }
                } else if type == "WebBookmarkTypeLeaf" {
                    if let uuid, let url = item["URLString"] as? String, !url.isEmpty {
                        urls[normalizeURL(url), default: []].append(uuid)
                    }
                }
            }
        }

        visit(items: rootChildren, isRootLevel: true)
        self.orderByUuid = orderMap
        self.urlQueues = urls
        self.folderQueues = folders
    }

    /// Standard Longest Increasing Subsequence positions ($O(n \log n)$). Siblings whose
    /// positions fall outside this set changed relative order and require CRDT position reset.
    static func longestIncreasingSubsequenceIndices(_ values: [Int]) -> Set<Int> {
        guard !values.isEmpty else { return [] }
        var tailIndices: [Int] = []
        var predecessors = Array(repeating: -1, count: values.count)

        for i in values.indices {
            let value = values[i]
            var low = 0
            var high = tailIndices.count
            while low < high {
                let mid = (low + high) / 2
                if values[tailIndices[mid]] < value {
                    low = mid + 1
                } else {
                    high = mid
                }
            }
            if low > 0 {
                predecessors[i] = tailIndices[low - 1]
            }
            if low == tailIndices.count {
                tailIndices.append(i)
            } else {
                tailIndices[low] = i
            }
        }

        var result = Set<Int>()
        var cursor = tailIndices.last ?? -1
        while cursor >= 0 {
            result.insert(cursor)
            cursor = predecessors[cursor]
        }
        return result
    }

    /// Keeps `Sync.ServerID` (assigning one if absent) while clearing `Sync.Data` and
    /// `Sync.ServerData` so `SafariBookmarksSyncAgent` computes a fresh CloudKit position/change.
    static func stripPositionData(
        in syncValue: Any?,
        serverIdFallback: () -> String
    ) -> [String: Any] {
        var sync = (syncValue as? [String: Any]) ?? [:]
        if (sync["ServerID"] as? String)?.isEmpty ?? true {
            sync["ServerID"] = serverIdFallback()
        }
        sync.removeValue(forKey: "Data")
        sync.removeValue(forKey: "ServerData")
        return sync
    }

    /// Prunes any descendants that survived in active folders (`usedUuids`) from a deleted
    /// folder's subtree and, when CloudKit sync is active, strips `Sync.Data` / `ServerData`
    /// while preserving/assigning `Sync.ServerID` on the deleted nodes.
    static func prepareDeletedSubtree(
        in dict: [String: Any],
        usedUuids: Set<String>,
        stripSyncPayload: Bool,
        assignMissingServerID: () -> String
    ) -> (dict: [String: Any], nodeCount: Int)? {
        if let uuid = dict["WebBookmarkUUID"] as? String, usedUuids.contains(uuid) {
            return nil
        }

        var updated = dict
        if stripSyncPayload {
            updated["Sync"] = stripPositionData(in: dict["Sync"], serverIdFallback: assignMissingServerID)
        }
        var count = 1

        if let children = dict["Children"] as? [[String: Any]] {
            var updatedChildren: [[String: Any]] = []
            updatedChildren.reserveCapacity(children.count)
            for child in children {
                if let prepared = prepareDeletedSubtree(
                    in: child,
                    usedUuids: usedUuids,
                    stripSyncPayload: stripSyncPayload,
                    assignMissingServerID: assignMissingServerID
                ) {
                    updatedChildren.append(prepared.dict)
                    count += prepared.nodeCount
                }
            }
            updated["Children"] = updatedChildren
        }
        return (updated, count)
    }

    static func syncNeedsRepair(_ syncValue: Any?) -> Bool {
        guard let sync = syncValue as? [String: Any] else { return true }
        guard let serverId = sync["ServerID"] as? String, !serverId.isEmpty else { return true }
        if let data = sync["Data"] as? Data, !data.isEmpty {
            return false
        }
        return true
    }
}
