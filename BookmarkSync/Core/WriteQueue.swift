import Foundation
import AppKit

final class WriteQueue: @unchecked Sendable {
    private final class LastWriteStore: @unchecked Sendable {
        private let lock = NSLock()
        private var times: [String: Date] = [:]

        func get(_ path: String) -> Date? {
            lock.lock()
            defer { lock.unlock() }
            return times[path]
        }

        func set(_ date: Date, for path: String) {
            lock.lock()
            times[path] = date
            lock.unlock()
        }
    }

    static let shared = WriteQueue()
    private static let lastWriteStore = LastWriteStore()
    weak var viewModel: AppViewModel?
    var onWriteConflict: (@Sendable (_ filePath: URL, _ bundleId: String) -> Void)?

    struct PendingWrite {
        let sequence: UInt64
        let parser: BrowserParser
        let nodes: [ParsedBookmark]
        let bundleId: String
        let expectedDiskFingerprint: String?
    }

    private var queue: [PendingWrite] = []
    private var nextSequence: UInt64 = 0
    private var lastMigrationResetTimes: [String: Date] = [:]
    private var lastInstanceWriteTimes: [String: Date] = [:]
    private var timer: Timer?
    private let queueLock = NSLock()
    private let writeLock = NSRecursiveLock()
    private let agentResetQueue = DispatchQueue(label: "BookmarkSync.SafariAgentReset", qos: .utility)

    private let startBackgroundMonitors: Bool
    private let resetter: SafariSyncAgentResetting
    private let liveSafariPathCheck: @Sendable (URL) -> Bool
    private let runningBundleIdsProvider: @Sendable () -> Set<String>
    private let migrationResetCooldown: TimeInterval
    private let quiescenceWindow: TimeInterval
    private let resetAsynchronously: Bool
    private let nowProvider: @Sendable () -> Date

    static func lastWriteTime(for path: String) -> Date? {
        lastWriteStore.get(path)
    }

    private static func recordLastWriteTime(_ date: Date, for path: String) {
        lastWriteStore.set(date, for: path)
    }

    func isWritePending(for bundleId: String) -> Bool {
        queueLock.lock()
        defer { queueLock.unlock() }
        return queue.contains { $0.bundleId == bundleId }
    }

    init(
        startBackgroundMonitors: Bool = true,
        resetter: SafariSyncAgentResetting = SystemSafariSyncAgentResetter(),
        liveSafariPathCheck: @escaping @Sendable (URL) -> Bool = { SafariSyncCoordinator.isLiveSafariPlistPath($0) },
        runningBundleIdsProvider: @escaping @Sendable () -> Set<String> = {
            Set(NSWorkspace.shared.runningApplications.filter { !$0.isTerminated }.compactMap { $0.bundleIdentifier })
        },
        migrationResetCooldown: TimeInterval = SafariSyncCoordinator.defaultMigrationResetCooldown,
        quiescenceWindow: TimeInterval = SafariSyncCoordinator.defaultQuiescenceWindow,
        resetAsynchronously: Bool = true,
        nowProvider: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.startBackgroundMonitors = startBackgroundMonitors
        self.resetter = resetter
        self.liveSafariPathCheck = liveSafariPathCheck
        self.runningBundleIdsProvider = runningBundleIdsProvider
        self.migrationResetCooldown = migrationResetCooldown
        self.quiescenceWindow = quiescenceWindow
        self.resetAsynchronously = resetAsynchronously
        self.nowProvider = nowProvider

        guard startBackgroundMonitors else { return }

        DispatchQueue.main.async {
            self.timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
                self?.flush()
            }
        }

        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(handleAppTermination(_:)),
            name: NSWorkspace.didTerminateApplicationNotification,
            object: nil
        )
    }

    func enqueue(
        parser: BrowserParser,
        nodes: [ParsedBookmark],
        bundleId: String,
        expectedDiskFingerprint: String? = nil
    ) {
        queueLock.lock()
        nextSequence += 1
        let seq = nextSequence
        // Remove existing pending writes for the same file to prevent queue buildup
        queue.removeAll { $0.parser.filePath.path == parser.filePath.path }
        queue.append(PendingWrite(
            sequence: seq,
            parser: parser,
            nodes: nodes,
            bundleId: bundleId,
            expectedDiskFingerprint: expectedDiskFingerprint
        ))
        queueLock.unlock()
        flush()
    }

    func removePendingWrites(for bookmarkFilePath: String) {
        queueLock.lock()
        let matching = queue.filter { $0.parser.filePath.path == bookmarkFilePath }
        queue.removeAll { $0.parser.filePath.path == bookmarkFilePath }
        let queuedBundleIds = Set(queue.map { $0.bundleId })
        queueLock.unlock()
        let running = runningBundleIdsProvider()
        publishAwaitingQuit(queuedBundleIds.intersection(running))

        for pending in matching {
            DispatchQueue.main.async { [weak self] in
                self?.viewModel?.markBrowserSynced(bundleId: pending.bundleId)
            }
        }
    }

    func flush() {
        writeLock.lock()
        defer { writeLock.unlock() }

        let runningApps = runningBundleIdsProvider()
        queueLock.lock()
        let snapshot = queue
        queueLock.unlock()

        var completedSequences = Set<UInt64>()
        var minRetryDelay: TimeInterval?

        for pending in snapshot {
            if runningApps.contains(pending.bundleId) {
                // Browser is running, wait until it quits to safely write
                SyncLog.verbose("WriteQueue: waiting for \(pending.bundleId) to quit before writing")
                continue
            }

            let fileURL = pending.parser.filePath
            let path = fileURL.path
            let isLiveSafari = liveSafariPathCheck(fileURL)
            let now = nowProvider()

            if isLiveSafari, migrationResetCooldown > 0,
               let lastReset = lastMigrationResetTimes[path] {
                let elapsed = now.timeIntervalSince(lastReset)
                if elapsed < migrationResetCooldown {
                    let delay = migrationResetCooldown - elapsed + 0.1
                    minRetryDelay = min(minRetryDelay ?? delay, delay)
                    SyncLog.verbose("WriteQueue: deferring Safari write during CloudKit migration cooldown (\(String(format: "%.1f", delay))s left)")
                    continue
                }
            }

            if isLiveSafari, quiescenceWindow > 0,
               let attrs = try? FileManager.default.attributesOfItem(atPath: path),
               let mtime = attrs[.modificationDate] as? Date {
                let ownWrite = lastInstanceWriteTimes[path]
                let isOwnRecentWrite = ownWrite.map {
                    mtime.timeIntervalSince($0) <= 0.5 && now.timeIntervalSince($0) < 3.0
                } ?? false
                let elapsed = now.timeIntervalSince(mtime)
                if !isOwnRecentWrite && elapsed >= 0 && elapsed < quiescenceWindow {
                    let delay = quiescenceWindow - elapsed + 0.1
                    minRetryDelay = min(minRetryDelay ?? delay, delay)
                    SyncLog.verbose("WriteQueue: waiting for Safari file quiescence (\(String(format: "%.1f", delay))s)")
                    continue
                }
            }

            if FileManager.default.fileExists(atPath: path) {
                do {
                    let liveNodes = try pending.parser.read()
                    let liveFingerprint = BookmarkSnapshotFingerprint.compute(liveNodes)
                    let targetFingerprint = BookmarkSnapshotFingerprint.compute(pending.nodes)

                    if liveFingerprint == targetFingerprint {
                        SyncLog.verbose("WriteQueue: \(pending.bundleId) already matches target tree; skipping write")
                        completedSequences.insert(pending.sequence)
                        DispatchQueue.main.async { [weak self, bundleId = pending.bundleId] in
                            self?.viewModel?.queueError = nil
                            self?.viewModel?.markBrowserSynced(bundleId: bundleId)
                        }
                        continue
                    }

                    if let expected = pending.expectedDiskFingerprint, liveFingerprint != expected {
                        SyncLog.event("WriteQueue: conflict on \(pending.bundleId); disk changed before write, aborting stale write")
                        completedSequences.insert(pending.sequence)
                        let conflictCallback = onWriteConflict
                        DispatchQueue.main.async { [weak self, bundleId = pending.bundleId] in
                            self?.viewModel?.queueError = nil
                            conflictCallback?(fileURL, bundleId)
                        }
                        continue
                    }
                } catch {
                    SyncLog.error("Pre-write verification failed for \(pending.bundleId): \(error)")
                    continue
                }
            }

            do {
                if let safariParser = pending.parser as? SafariParser {
                    let report = try safariParser.writeWithReport(nodes: pending.nodes)
                    lastInstanceWriteTimes[path] = now
                    WriteQueue.recordLastWriteTime(Date(), for: path)
                    SyncLog.event(
                        "Wrote bookmarks to \(pending.bundleId) (preserved=\(report.preservedCount), invalidated=\(report.invalidatedCount), created=\(report.createdCount), tombstoned=\(report.tombstonedCount), migrationReset=\(report.didRequestCloudKitMigration))"
                    )
                    if report.didRequestCloudKitMigration && isLiveSafari {
                        lastMigrationResetTimes[path] = now
                        triggerAgentReset()
                    }
                } else {
                    try pending.parser.write(nodes: pending.nodes)
                    lastInstanceWriteTimes[path] = now
                    WriteQueue.recordLastWriteTime(Date(), for: path)
                    SyncLog.event("Wrote bookmarks to \(pending.bundleId)")
                }

                completedSequences.insert(pending.sequence)
                DispatchQueue.main.async { [weak self, bundleId = pending.bundleId] in
                    self?.viewModel?.queueError = nil
                    self?.viewModel?.markBrowserSynced(bundleId: bundleId)
                }
            } catch {
                SyncLog.error("Write failed for \(pending.bundleId): \(error)")
                DispatchQueue.main.async { [weak self] in
                    self?.viewModel?.queueError = L10n.format("Write error (%@): %@", pending.bundleId, error.localizedDescription)
                }
            }
        }

        queueLock.lock()
        queue.removeAll { completedSequences.contains($0.sequence) }
        let awaitingQuit = Set(queue.map { $0.bundleId }.filter { runningApps.contains($0) })
        queueLock.unlock()

        publishAwaitingQuit(awaitingQuit)

        if startBackgroundMonitors, let delay = minRetryDelay {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                self?.flush()
            }
        }
    }

    private func triggerAgentReset() {
        let resetter = self.resetter
        if resetAsynchronously {
            agentResetQueue.async {
                resetter.resetSyncAgents()
            }
        } else {
            resetter.resetSyncAgents()
        }
    }

    /// Tells the menu bar which browsers must be quit before their writes land.
    private func publishAwaitingQuit(_ bundleIds: Set<String>) {
        DispatchQueue.main.async { [weak self] in
            guard let viewModel = self?.viewModel, viewModel.browsersAwaitingQuit != bundleIds else { return }
            viewModel.browsersAwaitingQuit = bundleIds
        }
    }
    
    @objc private func handleAppTermination(_ notification: Notification) {
        // Any app termination can be a signal that a browser has quit.
        // We flush immediately so that browser-specific queue items write independently.
        DispatchQueue.main.async { [weak self] in
            self?.flush()
        }
    }
}
