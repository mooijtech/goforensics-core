// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"github.com/jackc/pgx/v4"
)

// TreeNode represents a tree node which is presented in the filesystem.
type TreeNode struct {
	FolderUUID   string `json:"folder_uuid"`
	ProjectUUID  string `json:"project_uuid"`
	EvidenceUUID string `json:"evidence_uuid"`
	Title        string `json:"title"`
	Parent       string `json:"parent"`
}

// Save saves the tree node to the database.
func (treeNode *TreeNode) Save(database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO tree_nodes(folderUUID, projectUUID, evidenceUUID, title, parent) VALUES ($1, $2, $3, $4, %5)
	`
	_, err := database.Exec(context.Background(), preparedStatement, treeNode.FolderUUID, treeNode.ProjectUUID, treeNode.EvidenceUUID, treeNode.Title, treeNode.Parent)

	return err
}

// GetTreeNodesByParent returns the children of the tree node.
func GetTreeNodesByParent(parentTreeNodeUUID string, projectUUID string, database *pgx.Conn) ([]TreeNode, error) {
	preparedStatement := `
	SELECT * FROM tree_nodes WHERE projectUUID = $1 AND parent = $2
	`
	rows, err := database.Query(context.Background(), preparedStatement, projectUUID, parentTreeNodeUUID)

	if err != nil {
		return nil, err
	}

	var treeNodes []TreeNode
	var treeNode TreeNode

	for rows.Next() {
		err := rows.Scan(&treeNode.FolderUUID, &treeNode.ProjectUUID, &treeNode.EvidenceUUID, &treeNode.Title, &treeNode.Parent)

		if err != nil {
			return nil, err
		}

		treeNodes = append(treeNodes, treeNode)
	}

	rows.Close()

	return treeNodes, rows.Err()
}

// GetRootTreeNodes returns the root tree nodes of the project.
func GetRootTreeNodes(projectUUID string, database *pgx.Conn) ([]TreeNode, error) {
	return GetTreeNodesByParent("NULL", projectUUID, database)
}

// TreeNodeDTO represents a tree shown in the filesystem (this is a data transfer object).
type TreeNodeDTO struct {
	Value    string        `json:"value"`
	Label    string        `json:"label"`
	Children []TreeNodeDTO `json:"children"`
}

// WalkTreeNodeChildren returns all the children of this tree node.
func WalkTreeNodeChildren(treeNodeUUID string, projectUUID string, database *pgx.Conn) ([]TreeNodeDTO, error) {
	var treeNodeDTOs []TreeNodeDTO

	treeNodeChildren, err := GetTreeNodesByParent(treeNodeUUID, projectUUID, database)

	if err != nil {
		return nil, err
	}

	for _, treeNodeChild := range treeNodeChildren {
		treeNodeChildChildren, err := WalkTreeNodeChildren(treeNodeChild.FolderUUID, projectUUID, database)

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
func WalkTreeNodeChildrenUUIDs(treeNodeUUID string, projectUUID string, database *pgx.Conn) ([]string, error) {
	var treeNodeUUIDs []string

	treeNodeChildren, err := GetTreeNodesByParent(treeNodeUUID, projectUUID, database)

	if err != nil {
		return nil, err
	}

	for _, treeNodeChild := range treeNodeChildren {
		treeNodeUUIDs = append(treeNodeUUIDs, treeNodeChild.FolderUUID)

		treeNodeChildChildren, err := WalkTreeNodeChildrenUUIDs(treeNodeChild.FolderUUID, projectUUID, database)

		if err != nil {
			return nil, err
		}

		treeNodeUUIDs = append(treeNodeUUIDs, treeNodeChildChildren...)
	}

	return treeNodeUUIDs, nil
}
