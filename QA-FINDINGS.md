# RHEL 8 STIG V2R7 InSpec Profile — QA Findings

Audit performed against `baseline/U_RHEL_8_STIG_V2R7_Manual-xccdf.xml` as source of truth.
All issues below were identified and resolved unless noted otherwise.

---

## 1. Metadata Mismatches (97 controls)

Identified via `stig-qa.py`. The profile had been updated against a newer STIG release than V2R7,
causing metadata tags to drift from the XML source of truth.

### 1.1 Severity Wrong (3 controls) — **Fixed**

| Control | STIG ID | XML Severity | Profile Had |
|---|---|---|---|
| SV-230251 | RHEL-08-010290 | `high` | `medium` |
| SV-230252 | RHEL-08-010291 | `high` | `medium` |
| SV-230492 | RHEL-08-040010 | `medium` | `high` |

### 1.2 CCI Wrong (3 controls) — **Fixed**

| Control | STIG ID | Issue |
|---|---|---|
| SV-230356 | RHEL-08-020100 | Profile added `CCI-000192` not present in V2R7 |
| SV-230382 | RHEL-08-020350 | Profile added `CCI-000366` not present in V2R7 |
| SV-254520 | RHEL-08-040400 | Profile had `CCI-002265`; XML requires `CCI-002235` (wrong CCI entirely) |

### 1.3 `fix_id` Revision Drift (32 controls) — **Fixed**

Profile `fix_id` tags referenced a newer STIG revision than V2R7. All 32 corrected to match XML.

<details>
<summary>Full list</summary>

| Control | STIG ID |
|---|---|
| SV-230223 | RHEL-08-010020 |
| SV-230225 | RHEL-08-010040 |
| SV-230230 | RHEL-08-010100 |
| SV-230251 | RHEL-08-010290 |
| SV-230252 | RHEL-08-010291 |
| SV-230260 | RHEL-08-010330 |
| SV-230261 | RHEL-08-010340 |
| SV-230262 | RHEL-08-010350 |
| SV-230266 | RHEL-08-010372 |
| SV-230267 | RHEL-08-010373 |
| SV-230268 | RHEL-08-010374 |
| SV-230269 | RHEL-08-010375 |
| SV-230270 | RHEL-08-010376 |
| SV-230279 | RHEL-08-010423 |
| SV-230311 | RHEL-08-010671 |
| SV-230313 | RHEL-08-010673 |
| SV-230318 | RHEL-08-010700 |
| SV-230352 | RHEL-08-020060 |
| SV-230354 | RHEL-08-020080 |
| SV-230492 | RHEL-08-040010 |
| SV-230493 | RHEL-08-040020 |
| SV-230502 | RHEL-08-040070 |
| SV-230524 | RHEL-08-040140 |
| SV-230531 | RHEL-08-040172 |
| SV-230546 | RHEL-08-040282 |
| SV-230547 | RHEL-08-040283 |
| SV-230549 | RHEL-08-040285 |
| SV-230557 | RHEL-08-040350 |
| SV-244538 | RHEL-08-020081 |
| SV-244539 | RHEL-08-020082 |
| SV-251716 | RHEL-08-020104 |
| SV-254520 | RHEL-08-040400 |

</details>

### 1.4 `rid` Revision Drift (96 controls) — **Fixed**

All 96 control `rid` tags referenced newer STIG revision numbers than V2R7. All corrected.
These are cosmetic (revision stamp only) and have no effect on scan results, but affect
traceability back to the authoritative XML.

---

## 2. Check Logic Bugs (23 controls)

All identified and fixed. Verified by an independent second-pass review.

### 2.1 Check Always Passes (Silent Failures)

These controls would pass regardless of system state.

#### SV-230271 — RHEL-08-010380 — **Fixed**
**NOPASSWD sudoers filter — tautological contradiction**
```ruby
# BROKEN: tags.nil? && (tags || '').include?('NOPASSWD') is always false
# If tags is nil, the second condition can never be true
failing_results = sudoers(...).rules.where { tags.nil? && (tags || '').include?('NOPASSWD') }

# Also: exemption filter was applied when passwordless_admins IS nil (backwards)
failing_results = failing_results.where { ... } if input('passwordless_admins').nil?
```
**Fix:** Changed to `!tags.nil? && tags.include?('NOPASSWD')` and `unless` for the exemption filter.

#### SV-230311 — RHEL-08-010671 — **Fixed**
**`kernel_parameter` DSL method shadows local variable in regex**
```ruby
kernel_setting = 'kernel.core_pattern'
# Inside block, 'kernel_parameter' resolves to the InSpec DSL method, not kernel_setting
failing_k_conf = k_conf.reject { |k| k.match(/#{kernel_parameter}\s*=\s*#{kernel_expected_value}/) }
```
**Fix:** Changed to `Regexp.escape(kernel_setting)` and `Regexp.escape(kernel_expected_value)`.

#### SV-230329 — RHEL-08-010820 — **Fixed**
**Missing `should` keyword — assertion silently discarded**
```ruby
# BROKEN: 'cmp false' evaluates to a matcher object and is discarded
its('daemon.AutomaticLoginEnable') { cmp false }

# Fixed:
its('daemon.AutomaticLoginEnable') { should cmp false }
```

#### SV-230372 — RHEL-08-020250 — **Fixed**
**`pam_cert_auth` check in a dead branch**
```ruby
# BROKEN: only runs when sssd_conf_contents.params IS nil (SSSD not configured)
if sssd_conf_contents.params.nil?
  it 'should configure pam_cert_auth' do ...
  end
end
```
**Fix:** Moved check outside the nil condition with `unless sssd_conf_contents.params.nil?`.

#### SV-230384 — RHEL-08-020352 — **Fixed**
**`umask_set.nil?` is always false — no user is ever flagged**
```ruby
# BROKEN: command().stdout.strip returns String, never nil; short-circuits to false
umask_set = command("grep -ir ^umask #{u.home} ...").stdout.strip
umask_set.nil? && umask_set.match(/(?<umask>\d{3,4})/)['umask'].to_i > expected_mode.to_i
```
**Fix:** Replaced with empty-string check and correct octal comparison (`to_i(8)`).

### 2.2 Inverted Logic (Check Fails Compliant Systems)

#### SV-244521 — RHEL-08-010141 — **Fixed**
**GRUB superusers check requires `root` — the exact value that is a finding**
```ruby
# BROKEN: passes only when superusers IS set to "root" (which the STIG says is a finding)
its('set superusers') { should cmp '"root"' }
```
**Fix:** Changed to `should_not be_nil`, `should_not cmp '""'`, `should_not cmp '"root"'`.

#### SV-251711 — RHEL-08-010379 — **Fixed**
**`only_if` guard inverted — skips all real hosts, runs only inside Docker**
```ruby
# BROKEN: returns true only inside Docker without sudo — so only Docker gets checked
only_if(...) { virtualization.system.eql?('docker') && !command('sudo').exist? }
```
**Fix:** Added `!` negation.

#### SV-230376 — RHEL-08-020290 — **Fixed**
**Smart card applicability fully reversed — checks when N/A, skips when required**
```ruby
# BROKEN: skips when smart_card_enabled is true (when check IS required)
if input('smart_card_enabled')
  skip  # should be: perform check
else
  # perform check  (should be: N/A)
end
```
**Fix:** Swapped `if`/`else` branches.

### 2.3 Faillock Version Gate Inverted (8 controls) — **Fixed**

All eight faillock.conf controls used `only_if { os.version.minor.between?(0, 1) }`.
In InSpec, `only_if` **runs** the control when the block is `true`. This caused every control to:
- **Run** on RHEL 8.0/8.1 — where `/etc/security/faillock.conf` does not exist → error/finding
- **Skip** on RHEL 8.2+ — where the file exists and the check is required → N/A

**Fix:** Changed to `!os.version.minor.between?(0, 1)` in all eight controls.

| Control | STIG ID |
|---|---|
| SV-230333 | RHEL-08-020011 |
| SV-230335 | RHEL-08-020013 |
| SV-230337 | RHEL-08-020015 |
| SV-230339 | RHEL-08-020017 |
| SV-230341 | RHEL-08-020019 |
| SV-230343 | RHEL-08-020021 |
| SV-230345 | RHEL-08-020023 |
| SV-244534 | RHEL-08-020026 |

### 2.4 Wrong Value or Parameter

#### SV-230279 — RHEL-08-010423 — **Fixed**
**Checks `slub_debug=P` but V2R7 XML requires `init_on_free=1`**
The profile was written against an older STIG version. V2R7 changed the kernel parameter.
```ruby
# BROKEN (old STIG): checked slub_debug=P in grub2-editenv runtime output AND /etc/default/grub
# Fixed (V2R7): checks init_on_free=1 in /etc/default/grub only
```

#### SV-230337 — RHEL-08-020015 — **Fixed**
**`unlock_time` compared against `lockout_time` input instead of required value of `0`**
```ruby
# BROKEN: passes on any value >= lockout_time (e.g. 1800 seconds)
its('unlock_time') { should cmp >= input('lockout_time') }

# Fixed: STIG requires administrator-only release (unlock_time = 0)
its('unlock_time') { should cmp 0 }
```

#### SV-230544 — RHEL-08-040280 — **Fixed**
**Typo in IPv6 sysctl parameter name — parameter does not exist on Linux**
```ruby
# BROKEN: 'net.ipv6.conf.all.accept_redirect' does not exist
parameter = 'net.ipv6.conf.all.accept_redirect'

# Fixed:
parameter = 'net.ipv6.conf.all.accept_redirects'
```

#### SV-230223 — RHEL-08-010020 — **Fixed**
**Profile checked kernel FIPS mode; V2R7 XML requires crypto-policies check**
The control was written against an older STIG version. V2R7 changed the verification method.
- **Was:** `fips-mode-setup --check`, `grub2-editenv list | grep fips`, `/proc/sys/crypto/fips_enabled`
- **Now:** `update-crypto-policies --show` (must start with `FIPS`), hash algorithm validation in `/etc/crypto-policies/state/CURRENT.pol`, `min_rsa_size >= 2048`

#### SV-230374 — RHEL-08-020270 — **Fixed**
**Checks `warndays` (password warning) instead of account expiration date**
```ruby
# BROKEN: warndays is days before password expiry warning, not account expiry
failing_users = tmp_users_existing.select { |u| user(u).warndays > tmp_max_days }

# Fixed: uses 'chage -l' to get actual account expiration date
expiry_raw = command("chage -l #{u} | grep -i 'Account expires'").stdout
```

#### SV-230287 — RHEL-08-010490 — **Fixed**
**SSH private key search looks for `*.pem` — standard RHEL keys never have that extension**
```ruby
# BROKEN: finds nothing on standard RHEL 8 installations
priv_keys = command("find #{dirs} -xdev -name '*.pem'").stdout.split("\n")

# Fixed: matches standard SSH private key naming
priv_keys = command("find #{dirs} -xdev -name 'ssh_host*key'").stdout.split("\n")
```

### 2.5 Comparison Direction Reversed (3 controls)

All three used `<=` where the STIG requires a minimum value (`>=`).

| Control | STIG ID | Setting | Broken Check | Fixed Check |
|---|---|---|---|---|
| SV-230362 | RHEL-08-020160 | `minclass` | `be <= 4` (passes value of 1) | `be >= 4` |
| SV-230363 | RHEL-08-020170 | `difok` | `be <= 8` (passes value of 3) | `be >= 8` |
| SV-230365 | RHEL-08-020190 | `PASS_MIN_DAYS` | `cmp <= 1` (passes value of 0) | `cmp >= 1` |

### 2.6 Incorrect Field Checked

#### SV-230367 — RHEL-08-020210 — **Fixed**
**Per-user `maxdays` comparison used input scalar instead of per-user value**
```ruby
# BROKEN: 'value' is a local variable (input), not the per-user maxdays attribute
# 'value > 60' evaluates as '60 > 60' = false on every user — the > 60 case is never caught
value = input('pass_max_days')
bad_users = users.where { uid >= 1000 }.where { value > 60 or maxdays.negative? }

# Fixed: renamed to avoid shadowing, use maxdays directly
max_days = input('pass_max_days')
bad_users = users.where { uid >= 1000 }.where { maxdays > max_days || maxdays <= 0 }
```

### 2.7 Incomplete Checks (Missing Conditions)

#### SV-230280 — RHEL-08-010430 — **Fixed**
**ASLR only checked runtime value; persistent config file check was missing**
STIG requires verifying both `sysctl kernel.randomize_va_space` (runtime) and that the
setting is present in sysctl config files to survive reboots.
**Fix:** Added grep across `kernel_config_files` input with conflict detection.

#### SV-274877 — RHEL-08-030655 — **Fixed**
**Audit cron watch rules only checked for the path, not `-p wa` permissions**
```ruby
# BROKEN: a rule with only '-p x' (execute) would pass
its('lines') { should include %r{-w /etc/cron\.d/?} }

# Fixed: requires write/attribute-change permissions
its('lines') { should include %r{-w /etc/cron\.d/? -p wa} }
```

#### SV-251716 — RHEL-08-020104 — **Fixed**
**`pwquality retry` only checked lower bound; upper bound (`<= 3`) was missing**
```ruby
# BROKEN: retry = 999 would pass
its('retry') { should cmp >= input('min_retry') }

# Fixed: enforces 1 <= retry <= 3
its('retry') { should cmp >= 1 }
its('retry') { should cmp <= 3 }
```

#### SV-230284 — RHEL-08-010470 — **Fixed**
**`.shosts` search only matched the exact hidden filename, not `*.shosts` variants**
```ruby
# BROKEN: misses files like 'host.shosts', 'user.shosts'
command('find / -xdev -xautofs -name .shosts')

# Fixed:
command("find / -xdev -xautofs -name '*.shosts'")
```

### 2.8 N/A Condition Too Broad

#### SV-244527 — RHEL-08-010472 — **Fixed**
**`rng-tools` marked N/A for all RHEL 8.4+ systems; STIG only exempts 8.4+ with FIPS enabled**
```ruby
# BROKEN: skips check on all RHEL 8.4+ regardless of FIPS state
if os.version.minor >= 4
  skip

# Fixed: only N/A when 8.4+ AND kernel FIPS mode is active
fips_enabled = file('/proc/sys/crypto/fips_enabled').exist? &&
               file('/proc/sys/crypto/fips_enabled').content.strip == '1'
if os.version.minor >= 4 && fips_enabled
  skip
```

---

## 3. Library File Bugs

Found during library review. **None affect any current controls** — all are latent issues
in unused code paths.

### 3.1 `matchers.rb` — `all_without_args` logic inverted *(No current impact)*

`initialize_retval` returns `true` for `:all_without_args`, but `process_potentials` assigns
`retval = true` when the forbidden argument IS found and breaks when it is NOT found.
Net result: returns a match when all rules have the forbidden argument — the exact opposite
of the intended semantics.

**Current impact:** Zero controls in this profile use `all_without_args`. Would produce
inverted pass/fail results if a control ever uses it.

### 3.2 `pam.rb` — `rules_of_type` references `@services` from wrong class *(No current impact)*

`Rules` inherits from `Array` and never sets `@services`. The `@services` instance variable
belongs to the parent `Pam` class. `rules_of_type` always returns `[]`, making `first?` and
`last?` always return `false`.

**Current impact:** Zero controls call `first?`, `last?`, or `rules_of_type` directly.
All PAM controls use `match_pam_rule` which routes through `Rules#include?` (unaffected).

### 3.3 `random_number_generator.rb` — service detection always returns `false` *(No current impact)*

`systemctl show --no-pager --all <service>` outputs one property per line. The parser checks
for a line containing both the service name and "active" simultaneously — no single line
ever matches, so `rngd_running`, `haveged_running`, and `jitterentropy_running` are always `false`.

**Current impact:** Zero controls use this library resource. `SV-230285` uses InSpec's
built-in `service('rngd')` resource; `SV-244527` uses `package('rng-tools')`.

---

## 4. Minor Issues (Not Fixed)

### 4.1 `profile-inputs.yaml` — stale RHEL 7 header comment

The file header reads "This file specifies the attributes for the configurable controls
used in the RHEL 7 DISA STIG." The file was carried forward from the RHEL 7 profile.
The actual working input defaults are defined in `inspec.yml`. This file is not used
at scan time and has no functional impact, but is misleading.

### 4.2 SV-230384 — `uid_min` nil guard is dead code

```ruby
uid_min = login_defs.read_params['UID_MIN'].to_i
uid_min = 1000 if uid_min.nil?  # dead: .to_i on nil returns 0, not nil
```

If `UID_MIN` is absent from `/etc/login.defs`, `uid_min` becomes `0` and all users
(including system accounts) get their home directories scanned. `UID_MIN` is always
present in RHEL 8's default `/etc/login.defs`, so practical risk is negligible.

### 4.3 `SV-230279` — `desc 'fix'` references old `slub_debug` parameter

The fix text still mentions `grubby --args="slub_debug=P"`. The check was corrected to
`init_on_free=1` but the fix description was not updated. This is a documentation
inconsistency within the STIG itself (the STIG's own fix text may reference the old
parameter); it does not affect scan results.

---

## 5. QA Tools

`stig-qa.py` — saved at the repo root. Compares all `.rb` control metadata against the
XCCDF XML source of truth. Run from the repo root:

```bash
python3 stig-qa.py baseline/U_RHEL_8_STIG_V2R7_Manual-xccdf.xml
```

Fields compared per control: `gid`, `rid`, `severity`, `stig_id`, `fix_id`, `cci`.
