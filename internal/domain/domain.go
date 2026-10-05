// Package domain holds the core types shared across agent-db-scan: roles,
// database objects, resolved access, and the final report. Nothing in this
// package talks to Postgres — it's pure data.
package domain

import "time"

// ObjectKind identifies the kind of catalog object an ACL entry applies to.
type ObjectKind string

const (
	KindTable            ObjectKind = "table"
	KindView             ObjectKind = "view"
	KindMaterializedView ObjectKind = "materialized_view"
	KindSequence         ObjectKind = "sequence"
	KindFunction         ObjectKind = "function"
	KindForeignTable     ObjectKind = "foreign_table"
)

// AccessLevel is the risk classifier's bucket for a resolved access.
type AccessLevel string

const (
	AccessNone                AccessLevel = "none"
	AccessRead                AccessLevel = "read"
	AccessWrite               AccessLevel = "write"
	AccessAdmin               AccessLevel = "admin"
	AccessSuperuserEquivalent AccessLevel = "superuser_equivalent"
)

// AccessLevelRank orders AccessLevel from least to most privileged, so
// two levels can be compared numerically. Shared by internal/classify
// (naming-mismatch severity comparison) and internal/report (sorting
// output by severity) — keep it here as the single source of truth
// rather than letting each package define its own copy.
var AccessLevelRank = map[AccessLevel]int{
	AccessNone:                0,
	AccessRead:                1,
	AccessWrite:               2,
	AccessAdmin:               3,
	AccessSuperuserEquivalent: 4,
}

// ACLEntry mirrors a single entry from a Postgres aclitem array (e.g. one
// grantee's slice of a relacl or pg_default_acl.defaclacl).
type ACLEntry struct {
	Grantee     string   // role name, or "" / "PUBLIC" for a PUBLIC grant
	Privileges  []string // e.g. "SELECT", "INSERT", "UPDATE", "REFERENCES"
	GrantedBy   string
	GrantOption bool
}

// Role represents one row of pg_roles plus its direct pg_auth_members edges.
type Role struct {
	Name      string
	Inherit   bool // rolinherit
	Superuser bool // rolsuper
	CanLogin  bool // rolcanlogin
	BypassRLS bool // rolbypassrls
	MemberOf  []string
}

// DBObject is a scanned catalog object (table, view, sequence, function, ...).
type DBObject struct {
	Schema     string
	Name       string
	Kind       ObjectKind
	Owner      string
	ACL        []ACLEntry
	RLSEnabled bool
	RLSForced  bool
}

// AccessSource records one contributor to a login's effective access on
// an object — a direct grant, an inherited one, a PUBLIC grant, or
// ownership.
type AccessSource struct {
	Role       string   // role name this source came through ("" for PUBLIC/ownership if not role-shaped)
	Privileges []string // privileges this specific source contributes
	Kind       string   // "direct", "inherited", "public", "ownership"
	Inherited  bool     `json:",omitempty"` // Kind "ownership" only: Role owns the object and the login holds its rights through membership
}

// RLSPolicy mirrors one row of pg_policies — the resolved, human-readable
// view over pg_policy. Using the view instead of pg_policy directly avoids
// two nasty problems: polqual/polwithcheck are stored as pg_node_tree (an
// internal parsed-expression format, not readable SQL text — pg_policies
// already applies pg_get_expr() for you), and polroles is an array of role
// oids that the view has already resolved into names.
type RLSPolicy struct {
	Name       string
	Command    string   // ALL, SELECT, INSERT, UPDATE, DELETE
	Roles      []string // role names, or "public" for the PUBLIC pseudo-role
	Permissive bool
	UsingExpr  string
	CheckExpr  string
}

// RLSInfo captures a table's row-level security state: whether it's
// enabled/forced (pg_class.relrowsecurity / relforcerowsecurity) and the
// policies attached to it. Effective read/write access on a table with RLS
// enabled is necessarily narrower than the raw ACL suggests — the resolver
// and classifier both need to know this to avoid overstating access.
type RLSInfo struct {
	Schema   string
	Table    string
	Enabled  bool
	Forced   bool
	Policies []RLSPolicy
}

// EffectiveAccess is the resolver's answer for one object: what level of
// access the scanned login actually has, and why.
type EffectiveAccess struct {
	Object     DBObject
	Level      AccessLevel
	Privileges []string       // union of all privilege names this login effectively has on Object
	Sources    []AccessSource // every contributor, preserved individually — do not collapse
	RLS        *RLSInfo       // nil if the object has no row-level security; non-nil means RLS applies regardless of Level
}

// ForwardLookingAccess is a default privilege that will automatically
// apply to a future object matching ObjectKind, created by CreatorRole,
// in Schema (or database-wide if Schema == ""). It does not describe
// access to anything that exists yet — Postgres has no object to point
// to, only a standing rule that a future one will be covered — so this
// is intentionally a separate type from EffectiveAccess rather than a
// synthesized DBObject.
type ForwardLookingAccess struct {
	Schema      string // "" means database-wide
	CreatorRole string // defaclrole: whose future objects this applies to
	ObjectKind  ObjectKind
	Privileges  []string       // union of privileges the login would effectively get
	Sources     []AccessSource // direct / inherited / public — same shape as EffectiveAccess.Sources
}

// Report is the top-level scan result.
type Report struct {
	Login        string
	ScannedAt    time.Time
	Access       []EffectiveAccess
	FutureAccess []ForwardLookingAccess
	IndirectWritePaths []IndirectWritePath
	Warnings     []string
}

// SecurityDefinerFunction is a function or procedure marked SECURITY DEFINER:
// it runs with its owner's privileges, not the caller's. If the scanned login
// can execute one owned by a more privileged role, that's a potential
// indirect write path, even when the login has no table write privileges.
type SecurityDefinerFunction struct {
	Object           DBObject // Kind is KindFunction; Owner and ACL come from pg_proc
	Signature        string   // e.g. "public.reset_counter()"; functions can share a name, so we need the arguments too
	IsProcedure      bool     // true for procedures (called with CALL), false for functions
	OwnerSuperuser   bool     // the owner is a superuser, the worst case
	PinnedSearchPath bool     // the function sets its own search_path, which protects it from hijacking
}

// IndirectWritePath is a SecurityDefinerFunction the scanned login can
// actually execute, plus how it got that ability.
type IndirectWritePath struct {
	Function SecurityDefinerFunction
	Sources  []AccessSource // how the login gets EXECUTE: direct, inherited or PUBLIC
	Level    AccessLevel    // how dangerous the classifier thinks this is
}
