import Foundation

extension SafariParser {
    /// A UUID in the form Safari itself writes: UPPERCASE canonical.
    ///
    /// The inverse of Chrome's convention -- verified against a real
    /// Bookmarks.plist. `UUID().uuidString` is already uppercase on Apple
    /// platforms, so this is a named assertion of that requirement rather than a
    /// transformation: it keeps the intent explicit and survives anyone
    /// "tidying" the two parsers to match each other.
    private func newUuid() -> String {
        UUID().uuidString.uppercased()
    }

    func write(nodes: [ParsedBookmark]) throws {
        _ = try writeWithReport(nodes: nodes)
    }

    @discardableResult
    func writeWithReport(nodes: [ParsedBookmark]) throws -> SafariWriteReport {
        try performBackup()
        
        let strippedNodes = nodes.map { node in
            ParsedBookmark(
                id: stripProfileSetPrefix(node.id),
                title: node.title,
                url: node.url,
                type: node.type,
                parentId: node.parentId.map { stripProfileSetPrefix($0) },
                mtime: node.mtime,
                index: node.index
            )
        }

        // Group siblings once; the recursive tree build below then does O(1)
        // lookups instead of rescanning every node per folder.
        let childIndex = BookmarkChildIndex(strippedNodes: strippedNodes)
        
        let data = try Data(contentsOf: filePath)
        var root = try PropertyListSerialization.propertyList(from: data, options: .mutableContainersAndLeaves, format: nil) as! [String: Any]
        var rootChildren = root["Children"] as? [[String: Any]] ?? []
        
        var originalMapByTopologicalId: [String: String] = [:]
        var originalMapByUrl: [String: String] = [:]
        var originalMapByName: [String: [String]] = [:]
        var originalNodesByUuid: [String: [String: Any]] = [:]
        var parentUuidMap: [String: String] = [:]
        var existingDeletedFolder: [String: Any]? = nil
        var usedUuids: Set<String> = []
        var seenKeys: [String: Int] = [:]
        // Top-level entries of "other" that live directly at the plist root
        // rather than in the Bookmarks menu stay where they are.
        var rootLevelUuids: Set<String> = []
        
        func traverseOriginal(nodes: [[String: Any]], prefix: String, parentId: String?, parentUuid: String?) {
            for node in nodes {
                let name = Self.nodeTitle(in: node) ?? ""
                if name == "Deleted by BookmarkSync" && parentId == nil {
                    existingDeletedFolder = node
                    continue
                }
                
                let type = node["WebBookmarkType"] as? String
                let url = type == "WebBookmarkTypeLeaf" ? node["URLString"] as? String : nil
                
                let normalized = url != nil ? normalizeURL(url!) : name
                let baseId = parentId != nil ? "\(parentId!):\(normalized)" : "\(prefix):\(normalized)"
                
                let count = seenKeys[baseId, default: 0]
                seenKeys[baseId] = count + 1
                let uniqueId = count == 0 ? baseId : "\(baseId):dup\(count)"
                
                let uuid = node["WebBookmarkUUID"] as? String ?? newUuid()
                originalNodesByUuid[uuid] = node
                if let pUuid = parentUuid {
                    parentUuidMap[uuid] = pUuid
                }
                
                originalMapByTopologicalId[uniqueId] = uuid
                if let u = url {
                    originalMapByUrl[normalizeURL(u)] = uuid
                } else {
                    originalMapByName[name, default: []].append(uuid)
                }
                
                if let children = node["Children"] as? [[String: Any]] {
                    traverseOriginal(nodes: children, prefix: prefix, parentId: uniqueId, parentUuid: uuid)
                }
            }
        }
        
        if profileName == "Default" {
            if let node = rootChildren.first(where: { ($0["Title"] as? String) == "BookmarksBar" }), let children = node["Children"] as? [[String: Any]] {
                traverseOriginal(nodes: children, prefix: "bookmark_bar", parentId: nil, parentUuid: nil)
            }
            // Same order as `read`: the menu, then the user's top-level entries.
            let menuChildren = rootChildren.first(where: { ($0["Title"] as? String) == "BookmarksMenu" })?["Children"] as? [[String: Any]] ?? []
            traverseOriginal(nodes: menuChildren, prefix: BookmarkRoots.other, parentId: nil, parentUuid: nil)
            let rootEntries = rootChildren.filter(Self.isUserRootEntry)
            traverseOriginal(nodes: rootEntries, prefix: BookmarkRoots.other, parentId: nil, parentUuid: nil)
            for entry in rootEntries {
                if let uuid = entry["WebBookmarkUUID"] as? String { rootLevelUuids.insert(uuid) }
            }
            if let mobile = rootChildren.first(where: Self.isMobileFolder), let children = mobile["Children"] as? [[String: Any]] {
                traverseOriginal(nodes: children, prefix: BookmarkRoots.mobile, parentId: nil, parentUuid: nil)
            }
        } else {
            if let node = rootChildren.first(where: { ($0["Title"] as? String) == profileName }), let children = node["Children"] as? [[String: Any]] {
                traverseOriginal(nodes: children, prefix: "bookmark_bar", parentId: nil, parentUuid: nil)
            }
        }
        
        let hasRootSync = (root["Sync"] as? [String: Any]) != nil
        let cloudKitHelper = SafariCloudKitTreeHelper(rootChildren: rootChildren)
        var originalRootPrefixByUuid: [String: String] = [:]
        for (topoId, uuid) in originalMapByTopologicalId {
            if let rootPrefix = topoId.split(separator: ":", maxSplits: 1).first {
                originalRootPrefixByUuid[uuid] = String(rootPrefix)
            }
        }

        func isCompatibleType(_ origDict: [String: Any], with nodeType: BookmarkType) -> Bool {
            let expected = nodeType == .folder ? "WebBookmarkTypeList" : "WebBookmarkTypeLeaf"
            return (origDict["WebBookmarkType"] as? String) == expected
        }

        // Pre-reserve every exact topological match upfront so moved/renamed
        // items in earlier folders can never steal an unmoved sibling's UUID.
        var topologicalMatchesByNodeId: [String: String] = [:]
        var reservedTopologicalUuids: Set<String> = []
        for node in strippedNodes {
            if let candidate = originalMapByTopologicalId[node.id],
               !reservedTopologicalUuids.contains(candidate),
               let origDict = originalNodesByUuid[candidate],
               isCompatibleType(origDict, with: node.type) {
                topologicalMatchesByNodeId[node.id] = candidate
                reservedTopologicalUuids.insert(candidate)
            }
        }

        var needsCloudKitMigration = false
        var preservedCount = 0
        var invalidatedCount = 0
        var createdCount = 0
        var tombstonedCount = 0

        func claimFallbackUuid(
            for node: ParsedBookmark,
            candidates: [String]
        ) -> String? {
            for candidate in candidates {
                guard !usedUuids.contains(candidate),
                      !reservedTopologicalUuids.contains(candidate),
                      let origDict = originalNodesByUuid[candidate],
                      isCompatibleType(origDict, with: node.type) else {
                    continue
                }
                return candidate
            }
            return nil
        }

        func buildChildren(prefix: String, parentId: String?, parentUuid: String?) -> [[String: Any]] {
            let sortedChildren = childIndex.children(prefix: prefix, parentId: parentId)

            struct ClaimedSibling {
                let node: ParsedBookmark
                let uuid: String
                let origDict: [String: Any]?
                let sameParent: Bool
            }

            var claimed: [ClaimedSibling] = []
            claimed.reserveCapacity(sortedChildren.count)

            for node in sortedChildren {
                var matchedUuid: String?
                if let topoUuid = topologicalMatchesByNodeId[node.id], !usedUuids.contains(topoUuid) {
                    matchedUuid = topoUuid
                } else if node.type == .leaf, let url = node.url {
                    let candidates = cloudKitHelper.urlQueues[normalizeURL(url)] ?? []
                    let titlePreferred = candidates.filter {
                        originalNodesByUuid[$0].flatMap(Self.nodeTitle(in:)) == node.title
                    }
                    matchedUuid = claimFallbackUuid(for: node, candidates: titlePreferred + candidates)
                    if matchedUuid == nil, let fallback = originalMapByUrl[normalizeURL(url)] {
                        matchedUuid = claimFallbackUuid(for: node, candidates: [fallback])
                    }
                } else if node.type == .folder {
                    let named = (originalMapByName[node.title] ?? []) + (cloudKitHelper.folderQueues[node.title] ?? [])
                    let parentPreferred = named.filter { parentUuidMap[$0] == parentUuid }
                    matchedUuid = claimFallbackUuid(for: node, candidates: parentPreferred + named)
                }

                if let uuid = matchedUuid, let origDict = originalNodesByUuid[uuid] {
                    usedUuids.insert(uuid)
                    let sameParent: Bool
                    if let targetParentUuid = parentUuid {
                        sameParent = (parentUuidMap[uuid] == targetParentUuid)
                    } else {
                        sameParent = (parentUuidMap[uuid] == nil && originalRootPrefixByUuid[uuid] == prefix)
                    }
                    claimed.append(ClaimedSibling(node: node, uuid: uuid, origDict: origDict, sameParent: sameParent))
                } else {
                    let freshUuid = newUuid()
                    usedUuids.insert(freshUuid)
                    claimed.append(ClaimedSibling(node: node, uuid: freshUuid, origDict: nil, sameParent: false))
                }
            }

            var sameParentEntries: [(siblingIndex: Int, orderValue: Int)] = []
            for (idx, item) in claimed.enumerated() where item.sameParent {
                let orderValue = cloudKitHelper.orderByUuid[item.uuid] ?? idx
                sameParentEntries.append((siblingIndex: idx, orderValue: orderValue))
            }
            let anchoredOffsets = SafariCloudKitTreeHelper.longestIncreasingSubsequenceIndices(sameParentEntries.map(\.orderValue))
            var reorderedSiblingIndices = Set<Int>()
            for (offset, entry) in sameParentEntries.enumerated() where !anchoredOffsets.contains(offset) {
                reorderedSiblingIndices.insert(entry.siblingIndex)
            }

            return claimed.enumerated().map { idx, item in
                let node = item.node
                let childDicts: [[String: Any]]? = node.type == .folder
                    ? buildChildren(prefix: prefix, parentId: node.id, parentUuid: item.uuid)
                    : nil

                if var existing = item.origDict {
                    let sameType = isCompatibleType(existing, with: node.type)
                    let origTitle = Self.nodeTitle(in: existing) ?? "Unknown"
                    let sameTitle = origTitle == node.title
                    let sameURL: Bool = {
                        guard node.type == .leaf else { return true }
                        return (existing["URLString"] as? String) == node.url
                    }()
                    let isSemanticallyUnchanged = sameType && item.sameParent && sameTitle && sameURL && !reorderedSiblingIndices.contains(idx)

                    existing["WebBookmarkUUID"] = item.uuid
                    existing["Title"] = node.title
                    if node.type == .folder {
                        existing["WebBookmarkType"] = "WebBookmarkTypeList"
                        existing["Children"] = childDicts ?? []
                    } else {
                        existing["WebBookmarkType"] = "WebBookmarkTypeLeaf"
                        if let url = node.url {
                            existing["URLString"] = url
                            var uriDict = (existing["URIDictionary"] as? [String: Any]) ?? [:]
                            uriDict["title"] = node.title
                            existing["URIDictionary"] = uriDict
                        } else {
                            existing.removeValue(forKey: "URLString")
                        }
                    }

                    if hasRootSync {
                        if isSemanticallyUnchanged {
                            if SafariCloudKitTreeHelper.syncNeedsRepair(existing["Sync"]) {
                                var syncDict = (existing["Sync"] as? [String: Any]) ?? [:]
                                if (syncDict["ServerID"] as? String)?.isEmpty ?? true {
                                    syncDict["ServerID"] = newUuid()
                                }
                                existing["Sync"] = syncDict
                                needsCloudKitMigration = true
                                invalidatedCount += 1
                            } else {
                                preservedCount += 1
                            }
                        } else {
                            existing["Sync"] = SafariCloudKitTreeHelper.stripPositionData(
                                in: existing["Sync"],
                                serverIdFallback: newUuid
                            )
                            needsCloudKitMigration = true
                            invalidatedCount += 1
                        }
                    }
                    return existing
                }

                var dict: [String: Any] = [
                    "Title": node.title,
                    "WebBookmarkUUID": item.uuid
                ]
                if node.type == .folder {
                    dict["WebBookmarkType"] = "WebBookmarkTypeList"
                    dict["Children"] = childDicts ?? []
                } else {
                    dict["WebBookmarkType"] = "WebBookmarkTypeLeaf"
                    if let url = node.url {
                        dict["URLString"] = url
                        dict["URIDictionary"] = ["title": node.title]
                    }
                }
                if hasRootSync {
                    dict["Sync"] = ["ServerID": newUuid()]
                    needsCloudKitMigration = true
                    createdCount += 1
                }
                return dict
            }
        }

        func buildTree(prefix: String, parentId: String?) -> [[String: Any]] {
            buildChildren(prefix: prefix, parentId: parentId, parentUuid: nil)
        }
        
        let fBarChildren = buildTree(prefix: "bookmark_bar", parentId: nil)
        let otherChildren = buildTree(prefix: "other", parentId: nil)
        let isRootLevel: ([String: Any]) -> Bool = { entry in
            (entry["WebBookmarkUUID"] as? String).map { rootLevelUuids.contains($0) } ?? false
        }
        var bMenuChildren = otherChildren.filter { !isRootLevel($0) }
        let rootLevelChildren = otherChildren.filter(isRootLevel)
        let mobileChildren = profileName == "Default" ? buildTree(prefix: BookmarkRoots.mobile, parentId: nil) : []
        
        var newlyDeleted: [[String: Any]] = []
        for (uuid, origDict) in originalNodesByUuid {
            if !usedUuids.contains(uuid) {
                let pUuid = parentUuidMap[uuid]
                if pUuid == nil || usedUuids.contains(pUuid!) {
                    if let prepared = SafariCloudKitTreeHelper.prepareDeletedSubtree(
                        in: origDict,
                        usedUuids: usedUuids,
                        stripSyncPayload: hasRootSync,
                        assignMissingServerID: newUuid
                    ) {
                        newlyDeleted.append(prepared.dict)
                        if hasRootSync {
                            tombstonedCount += prepared.nodeCount
                            needsCloudKitMigration = true
                        }
                    }
                }
            }
        }
        
        if existingDeletedFolder != nil || !newlyDeleted.isEmpty {
            var deletedFolder = existingDeletedFolder ?? [
                "Title": "Deleted by BookmarkSync",
                "WebBookmarkType": "WebBookmarkTypeList",
                "WebBookmarkUUID": newUuid(),
                "Children": [[String: Any]]()
            ]
            if hasRootSync {
                var syncDict = (deletedFolder["Sync"] as? [String: Any]) ?? [:]
                if (syncDict["ServerID"] as? String)?.isEmpty ?? true {
                    syncDict["ServerID"] = newUuid()
                    deletedFolder["Sync"] = syncDict
                    needsCloudKitMigration = true
                }
            }
            var deletedChildren = deletedFolder["Children"] as? [[String: Any]] ?? []
            deletedChildren.append(contentsOf: newlyDeleted)
            deletedFolder["Children"] = deletedChildren
            
            bMenuChildren.append(deletedFolder)
        }
        
        if profileName == "Default" {
            // Rebuild the top level in place: Safari's own entries keep their
            // positions, the user's top-level entries go back where the first
            // of them was, and the mobile folder is created only when needed.
            var newRootChildren: [[String: Any]] = []
            var placedBar = false, placedMenu = false, placedRootLevel = false, placedMobile = false
            for entry in rootChildren {
                let title = entry["Title"] as? String
                if title == "BookmarksBar" && !placedBar {
                    var bar = entry
                    bar["Children"] = fBarChildren
                    newRootChildren.append(bar)
                    placedBar = true
                } else if title == "BookmarksMenu" && !placedMenu {
                    var menu = entry
                    menu["Children"] = bMenuChildren
                    newRootChildren.append(menu)
                    placedMenu = true
                } else if Self.isMobileFolder(entry) && !placedMobile {
                    var mobile = entry
                    mobile["Children"] = mobileChildren
                    newRootChildren.append(mobile)
                    placedMobile = true
                } else if Self.isUserRootEntry(entry) {
                    if !placedRootLevel {
                        newRootChildren.append(contentsOf: rootLevelChildren)
                        placedRootLevel = true
                    }
                } else {
                    newRootChildren.append(entry)
                }
            }
            if !placedRootLevel {
                newRootChildren.append(contentsOf: rootLevelChildren)
            }
            if !placedBar {
                newRootChildren.append(["Title": "BookmarksBar", "WebBookmarkType": "WebBookmarkTypeList", "Children": fBarChildren])
            }
            if !placedMenu {
                newRootChildren.append(["Title": "BookmarksMenu", "WebBookmarkType": "WebBookmarkTypeList", "Children": bMenuChildren])
            }
            if !placedMobile && !mobileChildren.isEmpty {
                newRootChildren.append([
                    "Title": Self.newMobileFolderTitle,
                    "WebBookmarkType": "WebBookmarkTypeList",
                    "WebBookmarkUUID": newUuid(),
                    "Children": mobileChildren
                ])
            }
            rootChildren = newRootChildren
        } else {
            if let idx = rootChildren.firstIndex(where: { ($0["Title"] as? String) == profileName }) {
                var profileNode = rootChildren[idx]
                profileNode["Children"] = fBarChildren
                rootChildren[idx] = profileNode
            } else {
                rootChildren.append([
                    "Title": profileName,
                    "WebBookmarkType": "WebBookmarkTypeList",
                    "Children": fBarChildren,
                    "WebBookmarkUUID": newUuid()
                ])
            }
        }
        
        root["Children"] = rootChildren
        if hasRootSync, needsCloudKitMigration, var rootSync = root["Sync"] as? [String: Any] {
            rootSync["CloudKitMigrationState"] = 0
            root["Sync"] = rootSync
        }
        let outData = try PropertyListSerialization.data(fromPropertyList: root, format: .binary, options: 0)
        try outData.write(to: filePath, options: .atomic)
        return SafariWriteReport(
            hasRootSync: hasRootSync,
            didRequestCloudKitMigration: hasRootSync && needsCloudKitMigration,
            preservedCount: preservedCount,
            invalidatedCount: invalidatedCount,
            createdCount: createdCount,
            tombstonedCount: tombstonedCount
        )
    }
}
