package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func NewIAMClient(ctx context.Context) (*iam.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(config.GetRegion()))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return iam.NewFromConfig(cfg), nil
}

// ScanIAM runs all IAM security checks and returns findings.
func ScanIAM(ctx context.Context) (*types.IAMScanResults, error) {
	client, err := NewIAMClient(ctx)
	if err != nil {
		return nil, err
	}

	res := &types.IAMScanResults{}

	checkRootAccountMFA(ctx, client, res)
	checkRootAccessKeys(ctx, client, res)
	checkPasswordPolicy(ctx, client, res)
	checkUsersWithoutMFA(ctx, client, res)
	checkAdminPolicies(ctx, client, res)
	checkStaleAccessKeys(ctx, client, res)

	return res, nil
}

// checkRootAccountMFA checks if the root account has MFA enabled.
func checkRootAccountMFA(ctx context.Context, client *iam.Client, res *types.IAMScanResults) {
	out, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "CHECK_FAILED", Severity: "HIGH",
			Resource: "root",
			Message:  fmt.Sprintf("Could not check root MFA: %v", err),
		})
		return
	}

	if out.SummaryMap["AccountMFAEnabled"] == 0 {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "ROOT_MFA_DISABLED", Severity: "CRITICAL",
			Resource: "root",
			Message:  "Root account does not have MFA enabled",
		})
		fmt.Println("[CRITICAL] Root account MFA is DISABLED")
	} else {
		fmt.Println("[SECURE]   Root account MFA is enabled")
	}

	if out.SummaryMap["AccountAccessKeysPresent"] > 0 {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "ROOT_ACCESS_KEY_EXISTS", Severity: "CRITICAL",
			Resource: "root",
			Message:  "Root account has active access keys — delete them immediately",
		})
		fmt.Println("[CRITICAL] Root account has active access keys")
	} else {
		fmt.Println("[SECURE]   No root account access keys found")
	}
}

// checkRootAccessKeys is a no-op since GetAccountSummary covers both checks above.
func checkRootAccessKeys(_ context.Context, _ *iam.Client, _ *types.IAMScanResults) {}

// checkPasswordPolicy checks the account password policy for weak settings.
func checkPasswordPolicy(ctx context.Context, client *iam.Client, res *types.IAMScanResults) {
	out, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "NO_PASSWORD_POLICY", Severity: "HIGH",
			Resource: "account",
			Message:  "No account password policy set — AWS defaults apply (very weak)",
		})
		fmt.Println("[HIGH]     No account password policy configured")
		return
	}

	p := out.PasswordPolicy

	if aws.ToInt32(p.MinimumPasswordLength) < 14 {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "WEAK_PASSWORD_LENGTH", Severity: "MEDIUM",
			Resource: "account",
			Message:  fmt.Sprintf("Minimum password length is %d (recommended: 14+)", aws.ToInt32(p.MinimumPasswordLength)),
		})
		fmt.Printf("[MEDIUM]   Password minimum length is %d (should be 14+)\n", aws.ToInt32(p.MinimumPasswordLength))
	} else {
		fmt.Printf("[SECURE]   Password minimum length is %d\n", aws.ToInt32(p.MinimumPasswordLength))
	}

	if !p.RequireUppercaseCharacters || !p.RequireLowercaseCharacters ||
		!p.RequireNumbers || !p.RequireSymbols {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "WEAK_PASSWORD_COMPLEXITY", Severity: "MEDIUM",
			Resource: "account",
			Message:  "Password policy does not require all character types (uppercase, lowercase, numbers, symbols)",
		})
		fmt.Println("[MEDIUM]   Password complexity requirements are incomplete")
	} else {
		fmt.Println("[SECURE]   Password complexity requirements are fully enforced")
	}

	if !p.ExpirePasswords {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "PASSWORDS_NEVER_EXPIRE", Severity: "MEDIUM",
			Resource: "account",
			Message:  "Password expiration is not enabled — passwords never expire",
		})
		fmt.Println("[MEDIUM]   Passwords never expire")
	} else {
		fmt.Printf("[SECURE]   Passwords expire after %d days\n", aws.ToInt32(p.MaxPasswordAge))
	}

	if aws.ToInt32(p.PasswordReusePrevention) == 0 {
		res.Findings = append(res.Findings, types.IAMFinding{
			Type: "PASSWORD_REUSE_ALLOWED", Severity: "LOW",
			Resource: "account",
			Message:  "Password reuse prevention is not configured — users can reuse old passwords",
		})
		fmt.Println("[LOW]      Password reuse prevention not configured")
	} else {
		fmt.Printf("[SECURE]   Last %d passwords cannot be reused\n", aws.ToInt32(p.PasswordReusePrevention))
	}
}

// checkUsersWithoutMFA lists IAM users that have a password but no MFA device.
func checkUsersWithoutMFA(ctx context.Context, client *iam.Client, res *types.IAMScanResults) {
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return
		}
		for _, user := range page.Users {
			username := aws.ToString(user.UserName)

			// Only check users that have console access (login profile)
			_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
				UserName: aws.String(username),
			})
			if err != nil {
				// No console access — skip
				continue
			}

			mfaOut, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: aws.String(username),
			})
			if err != nil || len(mfaOut.MFADevices) == 0 {
				res.Findings = append(res.Findings, types.IAMFinding{
					Type: "USER_MFA_DISABLED", Severity: "HIGH",
					Resource: username,
					Message:  fmt.Sprintf("User '%s' has console access but no MFA device", username),
				})
				fmt.Printf("[HIGH]     User '%s' has no MFA\\n", username)
			} else {
				fmt.Printf("[SECURE]   User '%s' has MFA enabled\\n", username)
			}
		}
	}
}

// checkAdminPolicies finds users/roles with AdministratorAccess or wildcard policies.
func checkAdminPolicies(ctx context.Context, client *iam.Client, res *types.IAMScanResults) {
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return
		}
		for _, user := range page.Users {
			username := aws.ToString(user.UserName)
			attached, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
				UserName: aws.String(username),
			})
			if err != nil {
				continue
			}
			for _, p := range attached.AttachedPolicies {
				pName := aws.ToString(p.PolicyName)
				if pName == "AdministratorAccess" {
					res.Findings = append(res.Findings, types.IAMFinding{
						Type: "ADMIN_POLICY_ATTACHED", Severity: "HIGH",
						Resource: username,
						Message:  fmt.Sprintf("User '%s' has AdministratorAccess policy attached", username),
					})
					fmt.Printf("[HIGH]     User '%s' has AdministratorAccess\\n", username)
				}
			}

			// Check inline policies for wildcard actions
			inlineOut, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
				UserName: aws.String(username),
			})
			if err != nil {
				continue
			}
			for _, pName := range inlineOut.PolicyNames {
				pDoc, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
					UserName:   aws.String(username),
					PolicyName: aws.String(pName),
				})
				if err != nil {
					continue
				}
				if strings.Contains(aws.ToString(pDoc.PolicyDocument), `"Action":"*"`) ||
					strings.Contains(aws.ToString(pDoc.PolicyDocument), `"Action": "*"`) {
					res.Findings = append(res.Findings, types.IAMFinding{
						Type: "WILDCARD_ACTION_POLICY", Severity: "HIGH",
						Resource: username,
						Message:  fmt.Sprintf("User '%s' has inline policy '%s' with wildcard Action (*)", username, pName),
					})
					fmt.Printf("[HIGH]     User '%s' inline policy '%s' uses Action:*\\n", username, pName)
				}
			}
		}
	}
}

// checkStaleAccessKeys flags access keys unused for more than 90 days.
func checkStaleAccessKeys(ctx context.Context, client *iam.Client, res *types.IAMScanResults) {
	const staleDays = 90
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return
		}
		for _, user := range page.Users {
			username := aws.ToString(user.UserName)
			keysOut, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: aws.String(username),
			})
			if err != nil {
				continue
			}
			for _, key := range keysOut.AccessKeyMetadata {
				keyID := aws.ToString(key.AccessKeyId)
				lastUsed, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
					AccessKeyId: aws.String(keyID),
				})
				if err != nil {
					continue
				}
				lu := lastUsed.AccessKeyLastUsed
				if lu == nil || lu.LastUsedDate == nil {
					// Key was never used — flag it
					res.Findings = append(res.Findings, types.IAMFinding{
						Type: "ACCESS_KEY_NEVER_USED", Severity: "MEDIUM",
						Resource: username,
						Message:  fmt.Sprintf("User '%s' has access key '%s' that was never used", username, keyID),
					})
					fmt.Printf("[MEDIUM]   User '%s' key '%s' never used\\n", username, keyID)
					continue
				}
				daysSince := int(time.Since(*lu.LastUsedDate).Hours() / 24)
				if daysSince > staleDays {
					res.Findings = append(res.Findings, types.IAMFinding{
						Type: "STALE_ACCESS_KEY", Severity: "MEDIUM",
						Resource: username,
						Message:  fmt.Sprintf("User '%s' has access key '%s' unused for %d days", username, keyID, daysSince),
					})
					fmt.Printf("[MEDIUM]   User '%s' key '%s' unused for %d days\\n", username, keyID, daysSince)
				} else {
					fmt.Printf("[SECURE]   User '%s' key '%s' used %d days ago\\n", username, keyID, daysSince)
				}
			}
		}
	}
}
