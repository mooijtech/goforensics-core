// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"github.com/emersion/go-message/mail"
	"github.com/jackc/pgx/v4"
	"strings"
)

// NetworkNode represents a node (contact) in the network.
type NetworkNode struct {
	ID   string `json:"id"`
	Size int    `json:"size"`
}

// NetworkLink represents a link (connection between two contacts) in the network.
type NetworkLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// Network represents a network of contacts and links.
type Network struct {
	Nodes                []NetworkNode `json:"nodes"`
	Links                []NetworkLink `json:"links"`
	FirstSentMessageDate int           `json:"first_sent_message_data"`
	LastSentMessageDate  int           `json:"last_sent_message_date"`
}

// GetNetwork returns the network of nodes (contacts) and links.
func GetNetwork(projectUUID string, database *pgx.Conn) (Network, error) {
	// Address X sent to address Y, Z amount of times
	sentMap := map[string]map[string]int{}

	var firstSentMessageDate int
	var lastSentMessageDate int

	allMessages, err := GetAllMessages(projectUUID, database)

	if err != nil {
		return Network{}, err
	}

	var messageIDs []string

	for _, message := range allMessages {
		// Dedupe based on the Message ID header or else it will inflate the count,
		// since one email can be stored in multiple mailboxes at the same time.
		if message.MessageID == messageNullValue || !containsMessageID(messageIDs, message.MessageID) {
			if message.MessageID != messageNullValue {
				messageIDs = append(messageIDs, message.MessageID)
			}

			// Populate first and last sent message time.
			if firstSentMessageDate == 0 {
				firstSentMessageDate = message.Received
			} else {
				if message.Received < firstSentMessageDate {
					firstSentMessageDate = message.Received
				}
			}

			if lastSentMessageDate == 0 {
				lastSentMessageDate = message.Received
			} else {
				if message.Received > lastSentMessageDate {
					lastSentMessageDate = message.Received
				}
			}

			// Populate the "Sent" map.
			for _, fromAddress := range getAddressesFromHeader(message.From) {
				_, hasSentMap := sentMap[fromAddress]

				if !hasSentMap {
					sentMap[fromAddress] = map[string]int{}
				}

				for _, toAddress := range getAddressesFromHeader(message.To) {
					_, hasSentMapToAddress := sentMap[fromAddress][toAddress]

					if !hasSentMapToAddress {
						sentMap[fromAddress][toAddress] = 1
					} else {
						sentMap[fromAddress][toAddress] = sentMap[fromAddress][toAddress] + 1
					}
				}

				for _, ccAddress := range getAddressesFromHeader(message.CC) {
					_, hasSentMapToAddress := sentMap[fromAddress][ccAddress]

					if !hasSentMapToAddress {
						sentMap[fromAddress][ccAddress] = 1
					} else {
						sentMap[fromAddress][ccAddress] = sentMap[fromAddress][ccAddress] + 1
					}
				}
			}
		}
	}

	var networkNodes []NetworkNode
	var networkLinks []NetworkLink

	// Add all nodes that have sent and received at least one message.
	for fromAddress, toAddresses := range sentMap {
		for toAddress, sentAmount := range toAddresses {
			if sentAmount > 0 {
				receivedAmount := sentMap[toAddress][fromAddress]

				if receivedAmount > 0 {
					if !containsNode(networkNodes, toAddress) {
						nodeSize := sentAmount * receivedAmount

						if nodeSize >= 30 {
							nodeSize = 30
						}

						networkNodes = append(networkNodes, NetworkNode{
							ID:   toAddress,
							Size: nodeSize,
						})
					}
					if !containsNode(networkNodes, fromAddress) {
						nodeSize := sentAmount * receivedAmount

						if nodeSize >= 30 {
							nodeSize = 30
						}

						networkNodes = append(networkNodes, NetworkNode{
							ID:   fromAddress,
							Size: nodeSize,
						})
					}
					if !containsLink(networkLinks, fromAddress, toAddress) {
						networkLinks = append(networkLinks, NetworkLink{
							Source: fromAddress,
							Target: toAddress,
						})
					}
				}
			}
		}
	}

	return Network{
		Nodes:                networkNodes,
		Links:                networkLinks,
		FirstSentMessageDate: firstSentMessageDate,
		LastSentMessageDate:  lastSentMessageDate,
	}, nil
}

func containsMessageID(messageIDs []string, wantedMessageID string) bool {
	containsMessageID := false

	for _, messageID := range messageIDs {
		if messageID == wantedMessageID {
			containsMessageID = true
		}
	}

	return containsMessageID
}

func containsLink(links []NetworkLink, source string, target string) bool {
	containsLink := false

	for _, link := range links {
		if link.Source == source && link.Target == target {
			containsLink = true
		}
	}

	return containsLink
}

func containsNode(nodes []NetworkNode, wantedNode string) bool {
	containsNode := false

	for _, node := range nodes {
		if node.ID == wantedNode {
			containsNode = true
		}
	}

	return containsNode
}

// getAddressesFromHeader returns all addresses from the header.
func getAddressesFromHeader(header string) []string {
	if header == messageNullValue {
		return []string{}
	}

	if strings.Contains(header, "; ") {
		headerAddresses := strings.Split(header, "; ")

		var addresses []string

		for _, address := range headerAddresses {
			addresses = append(addresses, address)
		}

		return addresses
	} else if !strings.Contains(header, "@") {
		return []string{header}
	} else {
		mailAddresses, err := mail.ParseAddressList(header)

		if err != nil {
			Logger.Errorf("Failed to parse address list: %s", err)
			return []string{}
		}

		var addresses []string

		for _, address := range mailAddresses {
			addresses = append(addresses, address.Address)
		}

		return addresses
	}
}
