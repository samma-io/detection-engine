package rulesdoc

import (
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
)

// TestDescribeCondition covers the rendering of a detection block into English.
//
// This is the only part of the catalogue with real logic, and it is the part
// that can be wrong without looking wrong: a mis-rendered condition reads
// perfectly well and tells the on-call the opposite of what the rule does.
func TestDescribeCondition(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "one field one value needs no parentheses",
			yaml: `
title: t
detection:
  selection:
    eventName: StopLogging
  condition: selection`,
			want: "`eventName` is `StopLogging`",
		},
		{
			name: "a value list reads as one of",
			yaml: `
title: t
detection:
  selection:
    action:
      - repo.access
      - repo.create
  condition: selection`,
			want: "`action` is one of `repo.access`, `repo.create`",
		},
		{
			name: "fields in one matcher are joined with and, unbracketed at top level",
			yaml: `
title: t
detection:
  selection:
    source: gcp
    protoPayload.methodName: CreateKey
  condition: selection`,
			want: "`source` is `gcp` and `protoPayload.methodName` is `CreateKey`",
		},
		{
			name: "a negated filter folds into the connective",
			yaml: `
title: t
detection:
  selection:
    userIdentity.type: Root
  filter:
    eventType: AwsServiceEvent
  condition: selection and not filter`,
			want: "`userIdentity.type` is `Root` **and not** `eventType` is `AwsServiceEvent`",
		},
		{
			name: "two searches combined get brackets only where they disambiguate",
			yaml: `
title: t
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: PutBucketAcl
  public:
    members: allUsers
  condition: selection and public`,
			want: "(`eventSource` is `s3.amazonaws.com` and `eventName` is `PutBucketAcl`) **and** `members` is `allUsers`",
		},
		{
			name: "a list of event matchers is an or",
			yaml: `
title: t
detection:
  selection:
    - action: org.update_member
      permission: admin
    - action: org.add_member
      permission: admin
  condition: selection`,
			want: "(`action` is `org.update_member` and `permission` is `admin`) or (`action` is `org.add_member` and `permission` is `admin`)",
		},
		{
			name: "modifiers are rendered as verbs",
			yaml: `
title: t
detection:
  selection:
    errorCode|startswith: AccessDenied
  condition: selection`,
			want: "`errorCode` starts with `AccessDenied`",
		},
		{
			name: "contains with a list reads as any of",
			yaml: `
title: t
detection:
  selection:
    scope|contains:
      - admin
      - files:read
  condition: selection`,
			want: "`scope` contains any of `admin`, `files:read`",
		},
		{
			name: "the all quantifier reads as all of, not as a modifier",
			yaml: `
title: t
detection:
  selection:
    scope|contains|all:
      - admin
      - files:read
  condition: selection`,
			want: "`scope` contains all of `admin`, `files:read`",
		},
		{
			name: "numeric comparators",
			yaml: `
title: t
detection:
  selection:
    permission_duration|gt: 3600
  condition: selection`,
			want: "`permission_duration` is greater than `3600`",
		},
		{
			name: "cidr",
			yaml: `
title: t
detection:
  selection:
    sourceIPAddress|cidr: 10.0.0.0/8
  condition: selection`,
			want: "`sourceIPAddress` is inside `10.0.0.0/8`",
		},
		{
			name: "one of pattern resolves the searches it names",
			yaml: `
title: t
detection:
  selection:
    eventName: CreateUser
  filter_a:
    errorCode: Denied
  filter_b:
    userAgent: terraform
  condition: selection and not 1 of filter_*`,
			want: "`eventName` is `CreateUser` **and not** (`errorCode` is `Denied` **or** `userAgent` is `terraform`)",
		},
		{
			name: "an or of two searches",
			yaml: `
title: t
detection:
  a:
    action: x
  b:
    action: y
  condition: a or b`,
			want: "`action` is `x` **or** `action` is `y`",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := sigma.ParseRule([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parsing the fixture: %v", err)
			}
			got := describeCondition(rule)
			if got != tc.want {
				t.Errorf("describeCondition()\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestDescribeFieldMatcher_UnknownModifierDoesNotVanish. Every modifier the
// engine admits has a phrase; if sigma-go ever gains one that this table does
// not know, the value must still be rendered rather than silently dropped.
func TestDescribeFieldMatcher_UnknownModifierDoesNotVanish(t *testing.T) {
	fm := sigma.FieldMatcher{
		Field:     "thing",
		Modifiers: []string{"someNewModifier"},
		Values:    []any{"value"},
	}
	got := describeFieldMatcher(fm)
	if got == "" {
		t.Fatal("an unknown modifier rendered as an empty string")
	}
	if want := "`thing` is `value`"; got != want {
		t.Errorf("got %q, want %q (falls back to the default phrasing)", got, want)
	}
}
