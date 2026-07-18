package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/SuryaTK2007/DriftShield/internal/config"
	"github.com/SuryaTK2007/DriftShield/internal/types"
)

func newIAMClient(ctx context.Context) (*iam.Client, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return iam.NewFromConfig(cfg), nil
}

// LoadIAMBaseline loads the IAM baseline from disk.
func LoadIAMBaseline() (*types.IAMBaseline, error) {
	if _, err := os.Stat(config.IAMBaselineFile); os.IsNotExist(err) {
		return nil, nil
	}
	data, err := os.ReadFile(config.IAMBaselineFile)
	if err != nil {
		return nil, err
	}
	var bl types.IAMBaseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, err
	}
	return &bl, nil
}

// SaveIAMBaseline saves the IAM baseline to disk.
func SaveIAMBaseline(bl *types.IAMBaseline) error {
	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config.IAMBaselineFile, data, 0644)
}

// CreateIAMBaseline snapshots the current IAM password policy and user states.
func CreateIAMBaseline(ctx context.Context) (*types.IAMBaseline, error) {
	client, err := newIAMClient(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().Format(time.RFC3339)
	bl := &types.IAMBaseline{
		CreatedAt: now,
		UpdatedAt: now,
		Users:     make(map[string]types.IAMUserSnapshot),
	}

	ppOut, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		bl.PasswordPolicy = types.IAMPasswordPolicySnapshot{Exists: false}
		fmt.Println("  Password policy: not configured")
	} else {
		p := ppOut.PasswordPolicy
		bl.PasswordPolicy = types.IAMPasswordPolicySnapshot{
			Exists:                  true,
			MinimumPasswordLength:   aws.ToInt32(p.MinimumPasswordLength),
			RequireUppercase:        p.RequireUppercaseCharacters,
			RequireLowercase:        p.RequireLowercaseCharacters,
			RequireNumbers:          p.RequireNumbers,
			RequireSymbols:          p.RequireSymbols,
			ExpirePasswords:         p.ExpirePasswords,
			MaxPasswordAge:          aws.ToInt32(p.MaxPasswordAge),
			PasswordReusePrevention: aws.ToInt32(p.PasswordReusePrevention),
		}
		fmt.Println("  Password policy: captured")
	}

	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
		for _, user := range page.Users {
			username := aws.ToString(user.UserName)
			snapshot := types.IAMUserSnapshot{Username: username}

			_, lerr := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: aws.String(username)})
			snapshot.HasConsoleAccess = lerr == nil

			mfaOut, merr := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: aws.String(username)})
			if merr == nil {
				snapshot.MFAEnabled = len(mfaOut.MFADevices) > 0
			}

			attached, aerr := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(username)})
			if aerr == nil {
				for _, p := range attached.AttachedPolicies {
					snapshot.AttachedPolicies = append(snapshot.AttachedPolicies, aws.ToString(p.PolicyName))
				}
			}

			keysOut, kerr := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(username)})
			if kerr == nil {
				for _, k := range keysOut.AccessKeyMetadata {
					snapshot.AccessKeyIDs = append(snapshot.AccessKeyIDs, aws.ToString(k.AccessKeyId))
				}
			}

			bl.Users[username] = snapshot
			fmt.Printf("  Captured user: %s\n", username)
		}
	}

	if err := SaveIAMBaseline(bl); err != nil {
		return nil, fmt.Errorf("failed to save IAM baseline: %w", err)
	}

	fmt.Printf("\nIAM baseline saved to %s\n", config.IAMBaselineFile)
	fmt.Printf("  %d user(s) captured\n", len(bl.Users))
	return bl, nil
}

// CompareIAMWithBaseline compares current IAM state against the baseline.
// Returns (drifts, baselineExists, error).
func CompareIAMWithBaseline(ctx context.Context) ([]types.IAMDrift, bool, error) {
	bl, err := LoadIAMBaseline()
	if err != nil {
		return nil, false, err
	}
	if bl == nil {
		return nil, false, nil
	}

	client, err := newIAMClient(ctx)
	if err != nil {
		return nil, true, err
	}

	fmt.Printf("Comparing against IAM baseline...\n\n")
	fmt.Printf("  Baseline created: %s\n\n", bl.CreatedAt)

	var drifts []types.IAMDrift

	// Password policy
	ppOut, ppErr := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if ppErr != nil {
		if bl.PasswordPolicy.Exists {
			drifts = append(drifts, types.IAMDrift{
				Type: "PASSWORD_POLICY_REMOVED", Resource: "account",
				Message: "Password policy was removed since baseline",
			})
			fmt.Println("[DRIFT]    Password policy was removed")
		} else {
			fmt.Println("[OK]       Password policy unchanged (still not configured)")
		}
	} else {
		p := ppOut.PasswordPolicy
		current := types.IAMPasswordPolicySnapshot{
			Exists:                  true,
			MinimumPasswordLength:   aws.ToInt32(p.MinimumPasswordLength),
			RequireUppercase:        p.RequireUppercaseCharacters,
			RequireLowercase:        p.RequireLowercaseCharacters,
			RequireNumbers:          p.RequireNumbers,
			RequireSymbols:          p.RequireSymbols,
			ExpirePasswords:         p.ExpirePasswords,
			MaxPasswordAge:          aws.ToInt32(p.MaxPasswordAge),
			PasswordReusePrevention: aws.ToInt32(p.PasswordReusePrevention),
		}
		if !bl.PasswordPolicy.Exists {
			drifts = append(drifts, types.IAMDrift{
				Type: "PASSWORD_POLICY_ADDED", Resource: "account",
				Message: "Password policy was added since baseline",
			})
			fmt.Println("[DRIFT]    Password policy was added")
		} else {
			policyDrifted := false
			if current.MinimumPasswordLength != bl.PasswordPolicy.MinimumPasswordLength {
				drifts = append(drifts, types.IAMDrift{
					Type: "PASSWORD_MIN_LENGTH_CHANGED", Resource: "account",
					Message:  "Minimum password length changed",
					OldValue: fmt.Sprintf("%d", bl.PasswordPolicy.MinimumPasswordLength),
					NewValue: fmt.Sprintf("%d", current.MinimumPasswordLength),
				})
				fmt.Printf("[DRIFT]    Password min length: %d -> %d\n", bl.PasswordPolicy.MinimumPasswordLength, current.MinimumPasswordLength)
				policyDrifted = true
			}
			if current.ExpirePasswords != bl.PasswordPolicy.ExpirePasswords {
				drifts = append(drifts, types.IAMDrift{
					Type: "PASSWORD_EXPIRY_CHANGED", Resource: "account",
					Message:  "Password expiration setting changed",
					OldValue: fmt.Sprintf("%v", bl.PasswordPolicy.ExpirePasswords),
					NewValue: fmt.Sprintf("%v", current.ExpirePasswords),
				})
				fmt.Printf("[DRIFT]    Password expiry: %v -> %v\n", bl.PasswordPolicy.ExpirePasswords, current.ExpirePasswords)
				policyDrifted = true
			}
			if current.PasswordReusePrevention != bl.PasswordPolicy.PasswordReusePrevention {
				drifts = append(drifts, types.IAMDrift{
					Type: "PASSWORD_REUSE_CHANGED", Resource: "account",
					Message:  "Password reuse prevention changed",
					OldValue: fmt.Sprintf("%d", bl.PasswordPolicy.PasswordReusePrevention),
					NewValue: fmt.Sprintf("%d", current.PasswordReusePrevention),
				})
				fmt.Printf("[DRIFT]    Password reuse prevention: %d -> %d\n", bl.PasswordPolicy.PasswordReusePrevention, current.PasswordReusePrevention)
				policyDrifted = true
			}
			if current.RequireUppercase != bl.PasswordPolicy.RequireUppercase ||
				current.RequireLowercase != bl.PasswordPolicy.RequireLowercase ||
				current.RequireNumbers != bl.PasswordPolicy.RequireNumbers ||
				current.RequireSymbols != bl.PasswordPolicy.RequireSymbols {
				drifts = append(drifts, types.IAMDrift{
					Type: "PASSWORD_COMPLEXITY_CHANGED", Resource: "account",
					Message: "Password complexity requirements changed",
				})
				fmt.Println("[DRIFT]    Password complexity requirements changed")
				policyDrifted = true
			}
			if !policyDrifted {
				fmt.Println("[OK]       Password policy unchanged")
			}
		}
	}

	// Users
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	currentUsers := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, true, fmt.Errorf("failed to list users: %w", err)
		}
		for _, user := range page.Users {
			username := aws.ToString(user.UserName)
			currentUsers[username] = true
			userDrifted := false

			blUser, exists := bl.Users[username]
			if !exists {
				drifts = append(drifts, types.IAMDrift{
					Type: "USER_ADDED", Resource: username,
					Message: fmt.Sprintf("User '%s' was added since baseline", username),
				})
				fmt.Printf("[DRIFT]    User '%s' added\n", username)
				continue
			}

			mfaOut, merr := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: aws.String(username)})
			currentMFA := merr == nil && len(mfaOut.MFADevices) > 0
			if currentMFA != blUser.MFAEnabled {
				drifts = append(drifts, types.IAMDrift{
					Type: "USER_MFA_CHANGED", Resource: username,
					Message:  fmt.Sprintf("User '%s' MFA status changed", username),
					OldValue: fmt.Sprintf("%v", blUser.MFAEnabled),
					NewValue: fmt.Sprintf("%v", currentMFA),
				})
				fmt.Printf("[DRIFT]    User '%s' MFA: %v -> %v\n", username, blUser.MFAEnabled, currentMFA)
				userDrifted = true
			}

			attached, aerr := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(username)})
			if aerr == nil {
				currentPolicies := make(map[string]bool)
				for _, pol := range attached.AttachedPolicies {
					currentPolicies[aws.ToString(pol.PolicyName)] = true
				}
				baselinePolicies := make(map[string]bool)
				for _, pol := range blUser.AttachedPolicies {
					baselinePolicies[pol] = true
				}
				for pol := range currentPolicies {
					if !baselinePolicies[pol] {
						drifts = append(drifts, types.IAMDrift{
							Type: "POLICY_ATTACHED", Resource: username,
							Message:  fmt.Sprintf("Policy '%s' attached to user '%s'", pol, username),
							NewValue: pol,
						})
						fmt.Printf("[DRIFT]    User '%s' policy added: %s\n", username, pol)
						userDrifted = true
					}
				}
				for pol := range baselinePolicies {
					if !currentPolicies[pol] {
						drifts = append(drifts, types.IAMDrift{
							Type: "POLICY_DETACHED", Resource: username,
							Message:  fmt.Sprintf("Policy '%s' detached from user '%s'", pol, username),
							OldValue: pol,
						})
						fmt.Printf("[DRIFT]    User '%s' policy removed: %s\n", username, pol)
						userDrifted = true
					}
				}
			}

			if !userDrifted {
				fmt.Printf("[OK]       User '%s' unchanged\n", username)
			}
		}
	}

	for username := range bl.Users {
		if !currentUsers[username] {
			drifts = append(drifts, types.IAMDrift{
				Type: "USER_DELETED", Resource: username,
				Message: fmt.Sprintf("User '%s' was deleted since baseline", username),
			})
			fmt.Printf("[DRIFT]    User '%s' deleted\n", username)
		}
	}

	return drifts, true, nil
}
