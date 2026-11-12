import XCTest
@testable import BookmarkSync

private final class SpyAgentResetter: SafariSyncAgentResetting, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var resetCount = 0

    func resetSyncAgents() {
        lock.lock()
        resetCount += 1
        lock.unlock()
    }
}

private final class LockedValue<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: T

    init(_ initial: T) {
        self.storage = initial
    }

    func get() -> T {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func set(_ newValue: T) {
        lock.lock()
        storage = newValue
        lock.unlock()
    }
}

private final class MutableTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(_ initial: Date) {
        self.current = initial
    }

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        current = current.addingTimeInterval(interval)
        lock.unlock()
    }
}

final class SafariCloudKitSyncTests: XCTestCase {
    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("SafariCloudKitSyncTests_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let tempDir {
            try? FileManager.default.removeItem(at: tempDir)
        }
    }

    // MARK: - Helpers

    private func plistURL(_ name: String = "Bookmarks.plist") -> URL {
        tempDir.appendingPathComponent(name)
    }

    private func leaf(
        title: String,
        url: String,
        uuid: String = UUID().uuidString.uppercased(),
        sync: [String: Any]? = nil,
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var dict: [String: Any] = [
            "Title": title,
            "URLString": url,
            "URIDictionary": ["title": title],
            "WebBookmarkType": "WebBookmarkTypeLeaf",
            "WebBookmarkUUID": uuid,
        ]
        if let sync { dict["Sync"] = sync }
        for (k, v) in extra { dict[k] = v }
        return dict
    }

    private func folder(
        title: String,
        uuid: String = UUID().uuidString.uppercased(),
        children: [[String: Any]] = [],
        sync: [String: Any]? = nil,
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var dict: [String: Any] = [
            "Title": title,
            "WebBookmarkType": "WebBookmarkTypeList",
            "WebBookmarkUUID": uuid,
            "Children": children,
        ]
        if let sync { dict["Sync"] = sync }
        for (k, v) in extra { dict[k] = v }
        return dict
    }

    private func writeSafariPlist(
        to url: URL,
        barChildren: [[String: Any]] = [],
        menuChildren: [[String: Any]] = [],
        rootSync: [String: Any]? = nil
    ) throws {
        var root: [String: Any] = [
            "Title": "",
            "WebBookmarkFileVersion": 1,
            "WebBookmarkType": "WebBookmarkTypeList",
            "WebBookmarkUUID": "ROOT-UUID",
            "Children": [
                folder(title: "BookmarksBar", uuid: "BAR-UUID", children: barChildren),
                folder(title: "BookmarksMenu", uuid: "MENU-UUID", children: menuChildren),
            ],
        ]
        if let rootSync {
            root["Sync"] = rootSync
        }
        let data = try PropertyListSerialization.data(fromPropertyList: root, format: .binary, options: 0)
        try data.write(to: url, options: .atomic)
    }

    private func readRawPlist(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(
            PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        )
    }

    private func childContainer(titled title: String, in root: [String: Any]) -> [[String: Any]] {
        let children = root["Children"] as? [[String: Any]] ?? []
        return children.first { ($0["Title"] as? String) == title }?["Children"] as? [[String: Any]] ?? []
    }

    private func collectAllUUIDsAndServerIDs(in nodes: [[String: Any]]) -> (uuids: [String], serverIDs: [String]) {
        var uuids: [String] = []
        var serverIDs: [String] = []
        for node in nodes {
            if let uuid = node["WebBookmarkUUID"] as? String {
                uuids.append(uuid)
            }
            if let sync = node["Sync"] as? [String: Any], let sid = sync["ServerID"] as? String {
                serverIDs.append(sid)
            }
            if let sub = node["Children"] as? [[String: Any]] {
                let nested = collectAllUUIDsAndServerIDs(in: sub)
                uuids.append(contentsOf: nested.uuids)
                serverIDs.append(contentsOf: nested.serverIDs)
            }
        }
        return (uuids, serverIDs)
    }

    // MARK: - CloudKit Sync Metadata Preservation & Invalidation

    func testUnchangedTreePreservesSyncMetadataAndLeavesMigrationStateUntouched() throws {
        let url = plistURL()
        let data1 = Data([1, 2, 3, 4])
        let data2 = Data([5, 6, 7, 8])
        let serverData = Data([9, 10])

        let swiftLeaf = leaf(
            title: "Swift",
            url: "https://swift.org",
            uuid: "LEAF-SWIFT",
            sync: ["ServerID": "SRV-SWIFT", "Data": data2, "ServerData": serverData],
            extra: ["ShouldOmitFromUI": false]
        )
        let devFolder = folder(
            title: "Dev",
            uuid: "FOLDER-DEV",
            children: [swiftLeaf],
            sync: ["ServerID": "SRV-DEV", "Data": data1]
        )
        let docsLeaf = leaf(
            title: "Docs",
            url: "https://docs.example.com",
            uuid: "LEAF-DOCS",
            sync: ["ServerID": "SRV-DOCS", "Data": data1]
        )

        try writeSafariPlist(
            to: url,
            barChildren: [devFolder, docsLeaf],
            rootSync: ["CloudKitMigrationState": 3, "ServerChangeToken": Data([0xAA])]
        )

        let parser = SafariParser(filePath: url)
        let nodes = try parser.read()
        let report = try parser.writeWithReport(nodes: nodes)

        XCTAssertTrue(report.hasRootSync)
        XCTAssertFalse(report.didRequestCloudKitMigration)
        XCTAssertEqual(report.preservedCount, 3)
        XCTAssertEqual(report.invalidatedCount, 0)
        XCTAssertEqual(report.createdCount, 0)
        XCTAssertEqual(report.tombstonedCount, 0)

        let rawRoot = try readRawPlist(url)
        let rawSync = rawRoot["Sync"] as? [String: Any]
        XCTAssertEqual(rawSync?["CloudKitMigrationState"] as? Int, 3)
        XCTAssertEqual(rawSync?["ServerChangeToken"] as? Data, Data([0xAA]))

        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        XCTAssertEqual(bar[0]["WebBookmarkUUID"] as? String, "FOLDER-DEV")
        XCTAssertEqual((bar[0]["Sync"] as? [String: Any])?["Data"] as? Data, data1)

        let devChildren = bar[0]["Children"] as? [[String: Any]] ?? []
        XCTAssertEqual(devChildren[0]["WebBookmarkUUID"] as? String, "LEAF-SWIFT")
        XCTAssertEqual(devChildren[0]["ShouldOmitFromUI"] as? Bool, false)
        let swiftSync = devChildren[0]["Sync"] as? [String: Any]
        XCTAssertEqual(swiftSync?["ServerID"] as? String, "SRV-SWIFT")
        XCTAssertEqual(swiftSync?["Data"] as? Data, data2)
        XCTAssertEqual(swiftSync?["ServerData"] as? Data, serverData)
    }

    func testInsertingNewBookmarkAssignsServerIDWithoutInvalidatingExistingSiblings() throws {
        let url = plistURL()
        let dataA = Data([0x0A])
        let dataB = Data([0x0B])

        try writeSafariPlist(
            to: url,
            barChildren: [
                leaf(title: "A", url: "https://a.com", uuid: "UUID-A", sync: ["ServerID": "SRV-A", "Data": dataA]),
                leaf(title: "B", url: "https://b.com", uuid: "UUID-B", sync: ["ServerID": "SRV-B", "Data": dataB]),
            ],
            rootSync: ["CloudKitMigrationState": 3]
        )

        let parser = SafariParser(filePath: url)
        var nodes = try parser.read()
        // Insert new bookmark between A and B.
        let inserted = ParsedBookmark(
            id: "bookmark_bar:mid.com",
            title: "Mid",
            url: "https://mid.com",
            type: .leaf,
            parentId: nil,
            mtime: Date(),
            index: 1
        )
        nodes = [
            nodes[0],
            inserted,
            ParsedBookmark(
                id: nodes[1].id,
                title: nodes[1].title,
                url: nodes[1].url,
                type: nodes[1].type,
                parentId: nodes[1].parentId,
                mtime: nodes[1].mtime,
                index: 2
            ),
        ]

        let report = try parser.writeWithReport(nodes: nodes)
        XCTAssertTrue(report.didRequestCloudKitMigration)
        XCTAssertEqual(report.preservedCount, 2)
        XCTAssertEqual(report.createdCount, 1)
        XCTAssertEqual(report.invalidatedCount, 0)

        let rawRoot = try readRawPlist(url)
        XCTAssertEqual((rawRoot["Sync"] as? [String: Any])?["CloudKitMigrationState"] as? Int, 0)

        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        XCTAssertEqual((bar[0]["Sync"] as? [String: Any])?["Data"] as? Data, dataA)
        XCTAssertNotNil((bar[1]["Sync"] as? [String: Any])?["ServerID"] as? String)
        XCTAssertNil((bar[1]["Sync"] as? [String: Any])?["Data"])
        XCTAssertEqual((bar[2]["Sync"] as? [String: Any])?["Data"] as? Data, dataB)
    }

    func testMoveAndRenameKeepServerIDAndStripPositionData() throws {
        let url = plistURL()
        let blob = Data([0x42])
        let srcFolder = folder(
            title: "Src",
            uuid: "UUID-SRC",
            children: [
                leaf(title: "Moved", url: "https://moved.com", uuid: "UUID-MOVED", sync: ["ServerID": "SRV-MOVED", "Data": blob, "ServerData": blob])
            ],
            sync: ["ServerID": "SRV-SRC", "Data": blob]
        )
        let dstFolder = folder(
            title: "Dst",
            uuid: "UUID-DST",
            children: [],
            sync: ["ServerID": "SRV-DST", "Data": blob]
        )
        let renamedLeaf = leaf(
            title: "Before",
            url: "https://rename.com",
            uuid: "UUID-RENAME",
            sync: ["ServerID": "SRV-RENAME", "Data": blob, "ServerData": blob]
        )

        try writeSafariPlist(
            to: url,
            barChildren: [srcFolder, dstFolder, renamedLeaf],
            rootSync: ["CloudKitMigrationState": 3]
        )

        let parser = SafariParser(filePath: url)
        let nodes = [
            ParsedBookmark(id: "bookmark_bar:Src", title: "Src", url: nil, type: .folder, parentId: nil, mtime: Date(), index: 0),
            ParsedBookmark(id: "bookmark_bar:Dst", title: "Dst", url: nil, type: .folder, parentId: nil, mtime: Date(), index: 1),
            ParsedBookmark(id: "bookmark_bar:Dst:moved.com", title: "Moved", url: "https://moved.com", type: .leaf, parentId: "bookmark_bar:Dst", mtime: Date(), index: 0),
            ParsedBookmark(id: "bookmark_bar:rename.com", title: "After", url: "https://rename.com", type: .leaf, parentId: nil, mtime: Date(), index: 2),
        ]

        let report = try parser.writeWithReport(nodes: nodes)
        XCTAssertTrue(report.didRequestCloudKitMigration)
        XCTAssertEqual(report.preservedCount, 2) // Src, Dst
        XCTAssertEqual(report.invalidatedCount, 2) // Moved leaf, Renamed leaf

        let rawRoot = try readRawPlist(url)
        XCTAssertEqual((rawRoot["Sync"] as? [String: Any])?["CloudKitMigrationState"] as? Int, 0)

        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        let dstChildren = bar[1]["Children"] as? [[String: Any]] ?? []
        XCTAssertEqual(dstChildren[0]["WebBookmarkUUID"] as? String, "UUID-MOVED")
        let movedSync = dstChildren[0]["Sync"] as? [String: Any]
        XCTAssertEqual(movedSync?["ServerID"] as? String, "SRV-MOVED")
        XCTAssertNil(movedSync?["Data"])
        XCTAssertNil(movedSync?["ServerData"])

        XCTAssertEqual(bar[2]["Title"] as? String, "After")
        let renameSync = bar[2]["Sync"] as? [String: Any]
        XCTAssertEqual(renameSync?["ServerID"] as? String, "SRV-RENAME")
        XCTAssertNil(renameSync?["Data"])
        XCTAssertNil(renameSync?["ServerData"])
    }

    func testReorderingSiblingsMinimallyInvalidatesMovedNodeOnly() throws {
        let url = plistURL()
        let blob = Data([0x77])
        try writeSafariPlist(
            to: url,
            barChildren: [
                leaf(title: "A", url: "https://a.com", uuid: "U-A", sync: ["ServerID": "S-A", "Data": blob]),
                leaf(title: "B", url: "https://b.com", uuid: "U-B", sync: ["ServerID": "S-B", "Data": blob]),
                leaf(title: "C", url: "https://c.com", uuid: "U-C", sync: ["ServerID": "S-C", "Data": blob]),
                leaf(title: "D", url: "https://d.com", uuid: "U-D", sync: ["ServerID": "S-D", "Data": blob]),
            ],
            rootSync: ["CloudKitMigrationState": 3]
        )

        let parser = SafariParser(filePath: url)
        let readNodes = try parser.read()
        // Move D to front: [D, A, B, C]
        let reordered = [readNodes[3], readNodes[0], readNodes[1], readNodes[2]].enumerated().map { idx, n in
            ParsedBookmark(id: n.id, title: n.title, url: n.url, type: n.type, parentId: n.parentId, mtime: n.mtime, index: idx)
        }

        let report = try parser.writeWithReport(nodes: reordered)
        XCTAssertTrue(report.didRequestCloudKitMigration)
        XCTAssertEqual(report.preservedCount, 3)
        XCTAssertEqual(report.invalidatedCount, 1)

        let rawRoot = try readRawPlist(url)
        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        let dSync = bar[0]["Sync"] as? [String: Any]
        XCTAssertEqual(dSync?["ServerID"] as? String, "S-D")
        XCTAssertNil(dSync?["Data"])
        XCTAssertEqual((bar[1]["Sync"] as? [String: Any])?["Data"] as? Data, blob)
        XCTAssertEqual((bar[2]["Sync"] as? [String: Any])?["Data"] as? Data, blob)
        XCTAssertEqual((bar[3]["Sync"] as? [String: Any])?["Data"] as? Data, blob)
    }

    func testDeletingFolderRecursivelyStripsSyncDataAndReSyncIsNoOp() throws {
        let url = plistURL()
        let blob = Data([0x55])
        let keep = leaf(title: "Keep", url: "https://keep.com", uuid: "U-KEEP", sync: ["ServerID": "S-KEEP", "Data": blob])
        let doomedChild = leaf(title: "Child", url: "https://child.com", uuid: "U-CHILD", sync: ["ServerID": "S-CHILD", "Data": blob, "ServerData": blob])
        let doomedFolder = folder(title: "Doomed", uuid: "U-DOOMED", children: [doomedChild], sync: ["ServerID": "S-DOOMED", "Data": blob])

        try writeSafariPlist(to: url, barChildren: [keep, doomedFolder], rootSync: ["CloudKitMigrationState": 3])

        let parser = SafariParser(filePath: url)
        let keepOnly = try parser.read().filter { $0.title == "Keep" }
        let report1 = try parser.writeWithReport(nodes: keepOnly)

        XCTAssertTrue(report1.didRequestCloudKitMigration)
        XCTAssertEqual(report1.tombstonedCount, 2)

        let rawRoot = try readRawPlist(url)
        XCTAssertEqual((rawRoot["Sync"] as? [String: Any])?["CloudKitMigrationState"] as? Int, 0)
        let menu = childContainer(titled: "BookmarksMenu", in: rawRoot)
        let deletedFolder = try XCTUnwrap(menu.first { ($0["Title"] as? String) == "Deleted by BookmarkSync" })
        XCTAssertNotNil((deletedFolder["Sync"] as? [String: Any])?["ServerID"] as? String)

        let deletedChildren = deletedFolder["Children"] as? [[String: Any]] ?? []
        let movedDoomed = try XCTUnwrap(deletedChildren.first { ($0["WebBookmarkUUID"] as? String) == "U-DOOMED" })
        XCTAssertEqual((movedDoomed["Sync"] as? [String: Any])?["ServerID"] as? String, "S-DOOMED")
        XCTAssertNil((movedDoomed["Sync"] as? [String: Any])?["Data"])
        let movedSub = (movedDoomed["Children"] as? [[String: Any]] ?? [])[0]
        XCTAssertEqual((movedSub["Sync"] as? [String: Any])?["ServerID"] as? String, "S-CHILD")
        XCTAssertNil((movedSub["Sync"] as? [String: Any])?["Data"])
        XCTAssertNil((movedSub["Sync"] as? [String: Any])?["ServerData"])

        // Simulate CloudKit completing sync and setting CloudKitMigrationState back to 3.
        var updatedRoot = rawRoot
        var syncDict = updatedRoot["Sync"] as? [String: Any] ?? [:]
        syncDict["CloudKitMigrationState"] = 3
        updatedRoot["Sync"] = syncDict
        try PropertyListSerialization.data(fromPropertyList: updatedRoot, format: .binary, options: 0).write(to: url)

        let report2 = try parser.writeWithReport(nodes: keepOnly)
        XCTAssertFalse(report2.didRequestCloudKitMigration)
        XCTAssertEqual(report2.tombstonedCount, 0)
        let rawRoot2 = try readRawPlist(url)
        XCTAssertEqual((rawRoot2["Sync"] as? [String: Any])?["CloudKitMigrationState"] as? Int, 3)
    }

    func testDuplicateURLsNeverReuseUUIDOrServerID() throws {
        let url = plistURL()
        let blob = Data([0x11])
        let f1 = folder(
            title: "F1",
            uuid: "U-F1",
            children: [
                leaf(title: "Link A", url: "https://dup.example.com", uuid: "U-D1", sync: ["ServerID": "S-D1", "Data": blob]),
                leaf(title: "Link B", url: "https://dup.example.com", uuid: "U-D2", sync: ["ServerID": "S-D2", "Data": blob]),
            ],
            sync: ["ServerID": "S-F1", "Data": blob]
        )
        let unmovedBar = leaf(title: "Bar Dup", url: "https://dup.example.com", uuid: "U-D3", sync: ["ServerID": "S-D3", "Data": blob])

        try writeSafariPlist(to: url, barChildren: [f1, unmovedBar], rootSync: ["CloudKitMigrationState": 3])

        let parser = SafariParser(filePath: url)
        // Rename folder F1 -> F1_New (forces children through fallback URL matcher) while keeping Bar Dup!
        let nodes = [
            ParsedBookmark(id: "bookmark_bar:F1_New", title: "F1_New", url: nil, type: .folder, parentId: nil, mtime: Date(), index: 0),
            ParsedBookmark(id: "bookmark_bar:F1_New:dup.example.com", title: "Link A", url: "https://dup.example.com", type: .leaf, parentId: "bookmark_bar:F1_New", mtime: Date(), index: 0),
            ParsedBookmark(id: "bookmark_bar:F1_New:dup.example.com:dup1", title: "Link B", url: "https://dup.example.com", type: .leaf, parentId: "bookmark_bar:F1_New", mtime: Date(), index: 1),
            ParsedBookmark(id: "bookmark_bar:dup.example.com", title: "Bar Dup", url: "https://dup.example.com", type: .leaf, parentId: nil, mtime: Date(), index: 1),
        ]

        _ = try parser.writeWithReport(nodes: nodes)
        let rawRoot = try readRawPlist(url)
        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        let menu = childContainer(titled: "BookmarksMenu", in: rawRoot)
        let collected = collectAllUUIDsAndServerIDs(in: bar + menu)

        XCTAssertEqual(Set(collected.uuids).count, collected.uuids.count, "Every UUID must be unique")
        XCTAssertEqual(Set(collected.serverIDs).count, collected.serverIDs.count, "Every Sync.ServerID must be unique")
        // Unmoved sibling kept U-D3 even though F1_New was visited earlier.
        XCTAssertEqual(bar[1]["WebBookmarkUUID"] as? String, "U-D3")
    }

    func testPlistWithoutRootSyncDoesNotSynthesizeSyncMetadata() throws {
        let url = plistURL()
        try writeSafariPlist(to: url, barChildren: [], rootSync: nil)

        let parser = SafariParser(filePath: url)
        let nodes = [
            ParsedBookmark(id: "bookmark_bar:example.com", title: "Example", url: "https://example.com", type: .leaf, parentId: nil, mtime: Date(), index: 0)
        ]
        let report = try parser.writeWithReport(nodes: nodes)

        XCTAssertFalse(report.hasRootSync)
        XCTAssertFalse(report.didRequestCloudKitMigration)

        let rawRoot = try readRawPlist(url)
        XCTAssertNil(rawRoot["Sync"])
        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        XCTAssertNil(bar[0]["Sync"])
    }

    func testSelfHealsExistingBookmarksMissingSyncDataWhenRootSyncExists() throws {
        let url = plistURL()
        try writeSafariPlist(
            to: url,
            barChildren: [
                leaf(title: "Local1", url: "https://local1.com", uuid: "U-L1", sync: nil),
                leaf(title: "Local2", url: "https://local2.com", uuid: "U-L2", sync: ["ServerID": "S-L2"]),
            ],
            rootSync: ["CloudKitMigrationState": 3]
        )

        let parser = SafariParser(filePath: url)
        let nodes = try parser.read()
        let report = try parser.writeWithReport(nodes: nodes)

        XCTAssertTrue(report.hasRootSync)
        XCTAssertTrue(report.didRequestCloudKitMigration)
        let rawRoot = try readRawPlist(url)
        XCTAssertEqual((rawRoot["Sync"] as? [String: Any])?["CloudKitMigrationState"] as? Int, 0)
        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        XCTAssertNotNil((bar[0]["Sync"] as? [String: Any])?["ServerID"] as? String)
        XCTAssertEqual((bar[1]["Sync"] as? [String: Any])?["ServerID"] as? String, "S-L2")
    }

    // MARK: - Fingerprint, CAS Lock, Quiescence & Cooldown

    func testSnapshotFingerprintIgnoresMtimeAndRespondsToSemanticEdits() {
        let t1 = Date(timeIntervalSince1970: 100)
        let t2 = Date(timeIntervalSince1970: 9999)
        let base = [
            ParsedBookmark(id: "bookmark_bar:a.com", title: "A", url: "https://a.com", type: .leaf, parentId: nil, mtime: t1, index: 0),
        ]
        let diffTime = [
            ParsedBookmark(id: "bookmark_bar:a.com", title: "A", url: "https://a.com", type: .leaf, parentId: nil, mtime: t2, index: 0),
        ]
        let renamed = [
            ParsedBookmark(id: "bookmark_bar:a.com", title: "B", url: "https://a.com", type: .leaf, parentId: nil, mtime: t1, index: 0),
        ]
        let reindexed = [
            ParsedBookmark(id: "bookmark_bar:a.com", title: "A", url: "https://a.com", type: .leaf, parentId: nil, mtime: t1, index: 1),
        ]

        XCTAssertEqual(BookmarkSnapshotFingerprint.compute(base), BookmarkSnapshotFingerprint.compute(diffTime))
        XCTAssertNotEqual(BookmarkSnapshotFingerprint.compute(base), BookmarkSnapshotFingerprint.compute(renamed))
        XCTAssertNotEqual(BookmarkSnapshotFingerprint.compute(base), BookmarkSnapshotFingerprint.compute(reindexed))
    }

    func testWriteQueueCASConflictAbortsStaleWriteAndSkipsResetForTempFiles() throws {
        let url = plistURL()
        try writeSafariPlist(
            to: url,
            barChildren: [leaf(title: "A", url: "https://a.com", uuid: "U-A")],
            rootSync: ["CloudKitMigrationState": 3]
        )

        let parser = SafariParser(filePath: url)
        let initialNodes = try parser.read()
        let expectedFP = BookmarkSnapshotFingerprint.compute(initialNodes)

        // Simulate concurrent iPhone sync-down modifying disk before WriteQueue flushes.
        let remoteNodes = initialNodes + [
            ParsedBookmark(id: "bookmark_bar:remote.com", title: "Remote", url: "https://remote.com", type: .leaf, parentId: nil, mtime: Date(), index: 1)
        ]
        try parser.write(nodes: remoteNodes)

        let spy = SpyAgentResetter()
        let writeQueue = WriteQueue(
            startBackgroundMonitors: false,
            resetter: spy,
            liveSafariPathCheck: { SafariSyncCoordinator.isLiveSafariPlistPath($0) },
            runningBundleIdsProvider: { [] },
            migrationResetCooldown: 0,
            quiescenceWindow: 0,
            resetAsynchronously: false
        )

        let conflictedPath = LockedValue<URL?>(nil)
        writeQueue.onWriteConflict = { path, _ in
            conflictedPath.set(path)
        }

        let staleLocalNodes = initialNodes + [
            ParsedBookmark(id: "bookmark_bar:local.com", title: "Local", url: "https://local.com", type: .leaf, parentId: nil, mtime: Date(), index: 1)
        ]
        writeQueue.enqueue(
            parser: parser,
            nodes: staleLocalNodes,
            bundleId: "com.apple.Safari",
            expectedDiskFingerprint: expectedFP
        )

        // Ensure main-async callback runs.
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))

        XCTAssertEqual(conflictedPath.get(), url)
        XCTAssertFalse(writeQueue.isWritePending(for: "com.apple.Safari"))
        XCTAssertEqual(spy.resetCount, 0)
        // Remote bookmark on disk must not be overwritten!
        let diskTitles = try parser.read().map(\.title)
        XCTAssertEqual(diskTitles, ["A", "Remote"])
    }

    func testWriteQueueQuiescenceAndMigrationResetCooldown() throws {
        let url = plistURL()
        let clock = MutableTestClock(Date(timeIntervalSince1970: 1_800_000_000))
        try writeSafariPlist(
            to: url,
            barChildren: [leaf(title: "A", url: "https://a.com", uuid: "U-A", sync: ["ServerID": "S-A", "Data": Data([1])])],
            rootSync: ["CloudKitMigrationState": 3]
        )
        // Simulate external agent touch 0.5s before `clock.now`.
        try FileManager.default.setAttributes([.modificationDate: clock.now.addingTimeInterval(-0.5)], ofItemAtPath: url.path)

        let spy = SpyAgentResetter()
        let writeQueue = WriteQueue(
            startBackgroundMonitors: false,
            resetter: spy,
            liveSafariPathCheck: { $0 == url },
            runningBundleIdsProvider: { [] },
            migrationResetCooldown: 20.0,
            quiescenceWindow: 1.5,
            resetAsynchronously: false,
            nowProvider: { clock.now }
        )

        let parser = SafariParser(filePath: url)
        let n0 = try parser.read()
        let n1 = n0 + [ParsedBookmark(id: "bookmark_bar:b.com", title: "B", url: "https://b.com", type: .leaf, parentId: nil, mtime: clock.now, index: 1)]

        // Within 1.5s external mtime quiescence -> defers.
        writeQueue.enqueue(parser: parser, nodes: n1, bundleId: "com.apple.Safari", expectedDiskFingerprint: BookmarkSnapshotFingerprint.compute(n0))
        XCTAssertTrue(writeQueue.isWritePending(for: "com.apple.Safari"))
        XCTAssertEqual(spy.resetCount, 0)

        // Advance past quiescence -> writes & triggers reset #1.
        clock.advance(by: 2.0)
        writeQueue.flush()
        XCTAssertFalse(writeQueue.isWritePending(for: "com.apple.Safari"))
        XCTAssertEqual(spy.resetCount, 1)

        // Queue second migration write 5s later (inside 20s cooldown) -> defers.
        clock.advance(by: 5.0)
        let n2 = n1 + [ParsedBookmark(id: "bookmark_bar:c.com", title: "C", url: "https://c.com", type: .leaf, parentId: nil, mtime: clock.now, index: 2)]
        writeQueue.enqueue(parser: parser, nodes: n2, bundleId: "com.apple.Safari", expectedDiskFingerprint: BookmarkSnapshotFingerprint.compute(n1))
        XCTAssertTrue(writeQueue.isWritePending(for: "com.apple.Safari"))
        XCTAssertEqual(spy.resetCount, 1)

        // Advance past 20s cooldown -> writes & triggers reset #2.
        clock.advance(by: 16.0)
        writeQueue.flush()
        XCTAssertFalse(writeQueue.isWritePending(for: "com.apple.Safari"))
        XCTAssertEqual(spy.resetCount, 2)
    }

    func testLiveSafariPathCheckRejectsTempFiles() {
        let home = URL(fileURLWithPath: "/Users/testuser")
        let live = home.appendingPathComponent("Library/Safari/Bookmarks.plist")
        XCTAssertTrue(SafariSyncCoordinator.isLiveSafariPlistPath(live, homeDirectory: home))
        XCTAssertFalse(SafariSyncCoordinator.isLiveSafariPlistPath(plistURL(), homeDirectory: home))
    }

    func testChromeToSafariRoundTripPreservesCloudKitSyncAndReadsCleanly() throws {
        let chromeURL = tempDir.appendingPathComponent("ChromeBookmarks.json")
        let safariURL = plistURL("SafariBookmarks.plist")
        let sharedBlob = Data([0x99, 0x88])

        let chromeJSON: [String: Any] = [
            "version": 1,
            "roots": [
                "bookmark_bar": [
                    "id": "1", "name": "Bookmarks bar", "type": "folder",
                    "date_added": "13000000000000000", "date_modified": "13000000000000000",
                    "children": [
                        ["id": "10", "name": "Shared", "type": "url", "url": "https://shared.example.com", "date_added": "13000000000000000"],
                        ["id": "11", "name": "FromEdgeOrChrome", "type": "url", "url": "https://chrome-new.example.com", "date_added": "13000000000000000"],
                    ],
                ],
                "other": ["id": "2", "name": "Other", "type": "folder", "date_added": "13000000000000000", "children": []],
                "synced": ["id": "3", "name": "Mobile", "type": "folder", "date_added": "13000000000000000", "children": []],
            ],
        ]
        try JSONSerialization.data(withJSONObject: chromeJSON).write(to: chromeURL)

        try writeSafariPlist(
            to: safariURL,
            barChildren: [
                leaf(title: "Shared", url: "https://shared.example.com", uuid: "U-SHARED", sync: ["ServerID": "S-SHARED", "Data": sharedBlob]),
                leaf(title: "DeletedOnChrome", url: "https://removed.example.com", uuid: "U-GONE", sync: ["ServerID": "S-GONE", "Data": sharedBlob, "ServerData": sharedBlob]),
            ],
            rootSync: ["CloudKitMigrationState": 3]
        )

        let chromeNodes = try ChromeParser(filePath: chromeURL).read()
        let safariParser = SafariParser(filePath: safariURL)
        let spy = SpyAgentResetter()
        let writeQueue = WriteQueue(
            startBackgroundMonitors: false,
            resetter: spy,
            liveSafariPathCheck: { $0 == safariURL },
            runningBundleIdsProvider: { [] },
            migrationResetCooldown: 0,
            quiescenceWindow: 0,
            resetAsynchronously: false
        )

        let expectedSafariFP = BookmarkSnapshotFingerprint.compute(try safariParser.read())
        writeQueue.enqueue(
            parser: safariParser,
            nodes: chromeNodes,
            bundleId: "com.apple.Safari",
            expectedDiskFingerprint: expectedSafariFP
        )

        XCTAssertEqual(spy.resetCount, 1)
        let rawRoot = try readRawPlist(safariURL)
        XCTAssertEqual((rawRoot["Sync"] as? [String: Any])?["CloudKitMigrationState"] as? Int, 0)

        let bar = childContainer(titled: "BookmarksBar", in: rawRoot)
        XCTAssertEqual(bar.count, 2)
        XCTAssertEqual((bar[0]["Sync"] as? [String: Any])?["Data"] as? Data, sharedBlob)
        XCTAssertNotNil((bar[1]["Sync"] as? [String: Any])?["ServerID"] as? String)

        let menu = childContainer(titled: "BookmarksMenu", in: rawRoot)
        let deleted = try XCTUnwrap(menu.first { ($0["Title"] as? String) == "Deleted by BookmarkSync" })
        let deletedChildren = deleted["Children"] as? [[String: Any]] ?? []
        XCTAssertEqual((deletedChildren[0]["Sync"] as? [String: Any])?["ServerID"] as? String, "S-GONE")
        XCTAssertNil((deletedChildren[0]["Sync"] as? [String: Any])?["Data"])
        XCTAssertNil((deletedChildren[0]["Sync"] as? [String: Any])?["ServerData"])

        let readBack = try safariParser.read()
        XCTAssertEqual(
            BookmarkSnapshotFingerprint.compute(readBack),
            BookmarkSnapshotFingerprint.compute(chromeNodes)
        )
    }
}
