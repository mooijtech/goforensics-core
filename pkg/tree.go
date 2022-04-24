// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

// TreeNode represents a tree node which is presented in the filesystem.
type TreeNode struct {
	FolderUUID   string `json:"folder_uuid"`
	EvidenceUUID string `json:"evidence_uuid"`
	Title        string `json:"title"`
	Parent       string `json:"parent"`
}

// Save saves the tree node to the database.
func (treeNode *TreeNode) Save(project Project) error {
	database, err := GetProjectDatabase(project)

	if err != nil {
		return err
	}

	defer func() {
		err = database.Close()

		if err != nil {
			Logger.Errorf("Failed to close database: %s", err)
		}
	}()

	statement, err := database.Prepare("INSERT INTO tree_nodes(folderUUID, evidenceUUID, title, parent) VALUES (?,?,?,?)")

	if err != nil {
		return err
	}

	_, err = statement.Exec(treeNode.FolderUUID, treeNode.EvidenceUUID, treeNode.Title, treeNode.Parent)

	if err != nil {
		return err
	}

	return nil
}

// GetRootTreeNodesByProject returns the root tree nodes of the project.
func GetRootTreeNodesByProject(project Project) ([]TreeNode, error) {
	database, err := GetProjectDatabase(project)

	if err != nil {
		return nil, err
	}

	defer func() {
		err = database.Close()

		if err != nil {
			Logger.Errorf("Failed to close database: %s", err)
		}
	}()

	rows, err := database.Query("SELECT * FROM tree_nodes WHERE parent = ?", "NULL")

	if err != nil {
		return nil, err
	}

	var treeNodes []TreeNode
	var treeNode TreeNode

	for rows.Next() {
		err := rows.Scan(&treeNode.FolderUUID, &treeNode.EvidenceUUID, &treeNode.Title, &treeNode.Parent)

		if err != nil {
			return nil, err
		}

		treeNodes = append(treeNodes, treeNode)
	}

	return treeNodes, nil
}

// GetTreeNodeChildrenByUUID returns the children of the tree node.
func GetTreeNodeChildrenByUUID(treeNodeUUID string, project Project) ([]TreeNode, error) {
	database, err := GetProjectDatabase(project)

	if err != nil {
		return nil, err
	}

	defer func() {
		err = database.Close()

		if err != nil {
			Logger.Errorf("Failed to close database: %s", err)
		}
	}()

	rows, err := database.Query("SELECT * FROM tree_nodes WHERE parent = ?", treeNodeUUID)

	if err != nil {
		return nil, err
	}

	var treeNodes []TreeNode
	var treeNode TreeNode

	for rows.Next() {
		err := rows.Scan(&treeNode.FolderUUID, &treeNode.EvidenceUUID, &treeNode.Title, &treeNode.Parent)

		if err != nil {
			return nil, err
		}

		treeNodes = append(treeNodes, treeNode)
	}

	return treeNodes, nil
}

// TreeNodeDTO represents a tree shown in the filesystem (this is a data transfer object).
type TreeNodeDTO struct {
	Value    string        `json:"value"`
	Label    string        `json:"label"`
	Children []TreeNodeDTO `json:"children"`
}

// WalkTreeNodeChildren returns all the children of this tree node.
func WalkTreeNodeChildren(treeNodeUUID string, project Project) ([]TreeNodeDTO, error) {
	var treeNodeDTOs []TreeNodeDTO

	treeNodeChildren, err := GetTreeNodeChildrenByUUID(treeNodeUUID, project)

	if err != nil {
		return nil, err
	}

	for _, treeNodeChild := range treeNodeChildren {
		treeNodeChildChildren, err := WalkTreeNodeChildren(treeNodeChild.FolderUUID, project)

		if err != nil {
			return nil, err
		}

		treeNodeDTOs = append(treeNodeDTOs, TreeNodeDTO{
			Value:    treeNodeChild.FolderUUID,
			Label:    treeNodeChild.Title,
			Children: treeNodeChildChildren,
		})
	}

	return treeNodeDTOs, nil
}

// WalkTreeNodeChildrenUUIDs returns all the tree node children UUIDs.
func WalkTreeNodeChildrenUUIDs(treeNodeUUID string, project Project) ([]string, error) {
	var treeNodeUUIDs []string

	treeNodeChildren, err := GetTreeNodeChildrenByUUID(treeNodeUUID, project)

	if err != nil {
		return nil, err
	}

	for _, treeNodeChild := range treeNodeChildren {
		treeNodeUUIDs = append(treeNodeUUIDs, treeNodeChild.FolderUUID)

		treeNodeChildChildren, err := WalkTreeNodeChildrenUUIDs(treeNodeChild.FolderUUID, project)

		if err != nil {
			return nil, err
		}

		treeNodeUUIDs = append(treeNodeUUIDs, treeNodeChildChildren...)
	}

	return treeNodeUUIDs, nil
}
