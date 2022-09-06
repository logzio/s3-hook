package main

type PolicyDocument struct {
	Version   string         `json:"Version"`
	Statement []StatementObj `json:"Statement"`
}

type StatementObj struct {
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
	Effect   string   `json:"Effect"`
}
