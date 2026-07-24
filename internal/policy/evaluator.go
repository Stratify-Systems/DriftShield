package policy

import (
	"context"
	"fmt"

	"github.com/SuryaTK2007/DriftShield/internal/baseline"
	"github.com/SuryaTK2007/DriftShield/internal/scanner"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

// EvaluatePolicyRules evaluates policy rules against current AWS resources.
func EvaluatePolicyRules(ctx context.Context, rules []PolicyRule) (*PolicyEvaluationResult, error) {
	res := &PolicyEvaluationResult{
		TotalRulesEvaluated: len(rules),
	}

	// Fetch snapshots once for performance and rate-limit prevention
	var s3Configs map[string]types.S3BucketConfig
	var ec2Details map[string]*types.SGDetails
	var iamFindings []types.IAMFinding
	var vpcSnapshots map[string]types.VPCSnapshot
	var rdsSnapshots map[string]types.RDSInstanceSnapshot
	var ctTrails []types.TrailSummary

	// Lazy snapshot fetchers
	getS3Configs := func() map[string]types.S3BucketConfig {
		if s3Configs == nil {
			s3Configs = make(map[string]types.S3BucketConfig)
			s3Results, err := scanner.ScanAllBuckets(ctx)
			if err == nil {
				for _, bucketName := range append(s3Results.Secure, s3Results.AtRisk...) {
					s3Configs[bucketName] = baseline.GetBucketConfig(ctx, nil, bucketName)
				}
			}
		}
		return s3Configs
	}

	getEC2Details := func() map[string]*types.SGDetails {
		if ec2Details == nil {
			ec2Results, err := scanner.ScanSecurityGroups(ctx)
			if err == nil {
				ec2Details = ec2Results.Details
			}
		}
		return ec2Details
	}

	getIAMFindings := func() []types.IAMFinding {
		if iamFindings == nil {
			iamResults, err := scanner.ScanIAM(ctx)
			if err == nil {
				iamFindings = iamResults.Findings
			}
		}
		return iamFindings
	}

	getVPCSnapshots := func() map[string]types.VPCSnapshot {
		if vpcSnapshots == nil {
			snaps, err := scanner.GetVPCSnapshot(ctx)
			if err == nil {
				vpcSnapshots = snaps
			}
		}
		return vpcSnapshots
	}

	getRDSSnapshots := func() map[string]types.RDSInstanceSnapshot {
		if rdsSnapshots == nil {
			snaps, err := scanner.GetRDSSnapshot(ctx)
			if err == nil {
				rdsSnapshots = snaps
			}
		}
		return rdsSnapshots
	}

	getCTTrails := func() []types.TrailSummary {
		if ctTrails == nil {
			ctResults, err := scanner.ScanCloudTrail(ctx)
			if err == nil {
				ctTrails = ctResults.Trails
			}
		}
		return ctTrails
	}

	for _, rule := range rules {
		rulePassed := true
		var ruleFindings []PolicyFinding

		switch rule.Service {
		case "s3":
			configs := getS3Configs()
			for bucketName, cfg := range configs {
				if ok, msg := evalS3Rule(rule, cfg); !ok {
					rulePassed = false
					ruleFindings = append(ruleFindings, PolicyFinding{
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Service:     rule.Service,
						Severity:    rule.Severity,
						Resource:    bucketName,
						Message:     msg,
						Remediation: rule.Remediation,
					})
				}
			}

		case "ec2":
			detailsMap := getEC2Details()
			for _, details := range detailsMap {
				if ok, msg := evalEC2Rule(rule, details.Config); !ok {
					rulePassed = false
					ruleFindings = append(ruleFindings, PolicyFinding{
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Service:     rule.Service,
						Severity:    rule.Severity,
						Resource:    fmt.Sprintf("%s (%s)", details.Config.GroupName, details.Config.GroupID),
						Message:     msg,
						Remediation: rule.Remediation,
					})
				}
			}

		case "iam":
			findings := getIAMFindings()
			for _, f := range findings {
				if f.Type == "USER_MFA_DISABLED" && rule.ID == "POL-IAM-001" {
					rulePassed = false
					ruleFindings = append(ruleFindings, PolicyFinding{
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Service:     rule.Service,
						Severity:    rule.Severity,
						Resource:    f.Resource,
						Message:     f.Message,
						Remediation: rule.Remediation,
					})
				}
			}

		case "vpc":
			snaps := getVPCSnapshots()
			for vpcID, snap := range snaps {
				if ok, msg := evalVPCRule(rule, snap); !ok {
					rulePassed = false
					ruleFindings = append(ruleFindings, PolicyFinding{
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Service:     rule.Service,
						Severity:    rule.Severity,
						Resource:    vpcID,
						Message:     msg,
						Remediation: rule.Remediation,
					})
				}
			}

		case "rds":
			snaps := getRDSSnapshots()
			for instanceID, snap := range snaps {
				if ok, msg := evalRDSRule(rule, snap); !ok {
					rulePassed = false
					ruleFindings = append(ruleFindings, PolicyFinding{
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Service:     rule.Service,
						Severity:    rule.Severity,
						Resource:    instanceID,
						Message:     msg,
						Remediation: rule.Remediation,
					})
				}
			}

		case "cloudtrail":
			trails := getCTTrails()
			for _, trail := range trails {
				if ok, msg := evalCloudTrailRule(rule, trail); !ok {
					rulePassed = false
					ruleFindings = append(ruleFindings, PolicyFinding{
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Service:     rule.Service,
						Severity:    rule.Severity,
						Resource:    trail.Name,
						Message:     msg,
						Remediation: rule.Remediation,
					})
				}
			}
		}

		if rulePassed {
			res.PassingRules++
		} else {
			res.FailingRules++
			res.Findings = append(res.Findings, ruleFindings...)
		}
	}

	return res, nil
}

// EvalS3BucketConfig evaluates a PolicyRule directly against an S3BucketConfig.
func EvalS3BucketConfig(rule PolicyRule, cfg types.S3BucketConfig) (bool, string) {
	return evalS3Rule(rule, cfg)
}

func evalS3Rule(rule PolicyRule, cfg types.S3BucketConfig) (bool, string) {
	for _, c := range rule.Conditions.All {
		switch c.Field {
		case "public_access_block.BlockPublicAcls":
			val := false
			if cfg.PublicAccessBlock != nil {
				val = cfg.PublicAccessBlock["BlockPublicAcls"]
			}
			if !checkBool(val, c.Operator, c.Value) {
				return false, fmt.Sprintf("BlockPublicAcls is %v (expected %v)", val, c.Value)
			}
		case "public_access_block.BlockPublicPolicy":
			val := false
			if cfg.PublicAccessBlock != nil {
				val = cfg.PublicAccessBlock["BlockPublicPolicy"]
			}
			if !checkBool(val, c.Operator, c.Value) {
				return false, fmt.Sprintf("BlockPublicPolicy is %v (expected %v)", val, c.Value)
			}
		case "versioning":
			if cfg.Versioning != fmt.Sprintf("%v", c.Value) {
				return false, fmt.Sprintf("Versioning is %s (expected %v)", cfg.Versioning, c.Value)
			}
		case "encryption":
			isEncrypted := (cfg.Encryption != "" && cfg.Encryption != "None")
			if targetBool, ok := c.Value.(bool); ok {
				if !checkBool(isEncrypted, c.Operator, targetBool) {
					return false, fmt.Sprintf("Encryption is %s (expected enabled = %v)", cfg.Encryption, targetBool)
				}
			} else if targetStr, isStr := c.Value.(string); isStr {
				if targetStr == "true" || targetStr == "false" {
					if !checkBool(isEncrypted, c.Operator, targetStr == "true") {
						return false, fmt.Sprintf("Encryption is %s (expected enabled = %s)", cfg.Encryption, targetStr)
					}
				} else if cfg.Encryption != targetStr {
					return false, fmt.Sprintf("Encryption is %s (expected %s)", cfg.Encryption, targetStr)
				}
			}
		}
	}
	return true, ""
}

// EvalSGConfig evaluates a PolicyRule directly against an SGConfig.
func EvalSGConfig(rule PolicyRule, cfg types.SGConfig) (bool, string) {
	return evalEC2Rule(rule, cfg)
}

func evalEC2Rule(rule PolicyRule, cfg types.SGConfig) (bool, string) {
	if rule.Conditions.NoneRule != nil {
		target := rule.Conditions.NoneRule
		for _, r := range cfg.InboundRules {
			if r.Protocol == target.Protocol || target.Protocol == "" {
				if r.FromPort <= target.Port && target.Port <= r.ToPort {
					for _, src := range r.Sources {
						if src == target.Source || target.Source == "" {
							return false, fmt.Sprintf("Inbound rule allows %s port %d from %s", r.Protocol, target.Port, src)
						}
					}
				}
			}
		}
	}
	return true, ""
}

// EvalVPCSnapshot evaluates a PolicyRule directly against a VPCSnapshot.
func EvalVPCSnapshot(rule PolicyRule, snap types.VPCSnapshot) (bool, string) {
	return evalVPCRule(rule, snap)
}

func evalVPCRule(rule PolicyRule, snap types.VPCSnapshot) (bool, string) {
	for _, c := range rule.Conditions.All {
		if c.Field == "flow_logs_enabled" {
			if !checkBool(snap.FlowLogsEnabled, c.Operator, c.Value) {
				return false, fmt.Sprintf("VPC flow logs enabled = %v (expected %v)", snap.FlowLogsEnabled, c.Value)
			}
		}
	}
	return true, ""
}

// EvalRDSInstanceSnapshot evaluates a PolicyRule directly against an RDSInstanceSnapshot.
func EvalRDSInstanceSnapshot(rule PolicyRule, snap types.RDSInstanceSnapshot) (bool, string) {
	return evalRDSRule(rule, snap)
}

func evalRDSRule(rule PolicyRule, snap types.RDSInstanceSnapshot) (bool, string) {
	for _, c := range rule.Conditions.All {
		switch c.Field {
		case "storage_encrypted":
			if !checkBool(snap.StorageEncrypted, c.Operator, c.Value) {
				return false, fmt.Sprintf("StorageEncrypted = %v (expected %v)", snap.StorageEncrypted, c.Value)
			}
		case "publicly_accessible":
			if !checkBool(snap.PubliclyAccessible, c.Operator, c.Value) {
				return false, fmt.Sprintf("PubliclyAccessible = %v (expected %v)", snap.PubliclyAccessible, c.Value)
			}
		case "deletion_protection":
			if !checkBool(snap.DeletionProtection, c.Operator, c.Value) {
				return false, fmt.Sprintf("DeletionProtection = %v (expected %v)", snap.DeletionProtection, c.Value)
			}
		}
	}
	return true, ""
}

// EvalTrailSummary evaluates a PolicyRule directly against a TrailSummary.
func EvalTrailSummary(rule PolicyRule, trail types.TrailSummary) (bool, string) {
	return evalCloudTrailRule(rule, trail)
}

func evalCloudTrailRule(rule PolicyRule, trail types.TrailSummary) (bool, string) {
	for _, c := range rule.Conditions.All {
		switch c.Field {
		case "is_logging":
			if !checkBool(trail.IsLogging, c.Operator, c.Value) {
				return false, fmt.Sprintf("Trail IsLogging = %v (expected %v)", trail.IsLogging, c.Value)
			}
		case "log_validation":
			if !checkBool(trail.LogValidation, c.Operator, c.Value) {
				return false, fmt.Sprintf("Trail LogValidation = %v (expected %v)", trail.LogValidation, c.Value)
			}
		}
	}
	return true, ""
}

func checkBool(actual bool, operator string, target interface{}) bool {
	targetBool, ok := target.(bool)
	if !ok {
		if targetStr, isStr := target.(string); isStr {
			targetBool = (targetStr == "true")
		}
	}

	switch operator {
	case "equals", "is_true":
		return actual == targetBool
	case "not_equals", "is_false":
		return actual != targetBool
	default:
		return actual == targetBool
	}
}
