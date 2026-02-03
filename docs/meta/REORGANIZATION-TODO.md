# Documentation Reorganization TODO

## Issues Identified

1. **Odin doc mixes Gateway configs with Odin tool info**
   - File: `gateway/82-odin-routines-database-UNHASHED.md`
   - Problem: Contains both Odin database AND Gateway config mappings
   - Solution: Split into focused documents

2. **Gateway config database incomplete**
   - File: `gateway/77-gateway-config-database-REAL.md`
   - Problem: Only has ~100 configs, we have 662
   - Solution: Add ALL configs with security classifications

3. **Duplicate/scattered info**
   - Config security levels mentioned in 3+ places
   - gw-diag commands in multiple docs
   - Needs consolidation

## Reorganization Plan

### Phase 1: Gateway Config Database (HIGH PRIORITY)

**File: `gateway/77-gateway-config-database-REAL.md`**

Add:
- [ ] Complete table of all 662 configs
- [ ] Security level for each (UDP/Hermes/GTW)
- [ ] Known config names (from strings + Odin)
- [ ] Split vehicle configs (0x0000-0x01FF) from CAN data (0x4000+)
- [ ] accessId mapping from Odin database
- [ ] Example values from real dump

Structure:
```
## Vehicle Configs (0x0000-0x01FF)
| Config ID | Name | Security | accessId | Example Value |
|-----------|------|----------|----------|---------------|

## CAN Data Configs (0x4000-0x7FFF)
| Config ID | Length | Description |
|-----------|--------|-------------|
```

### Phase 2: Odin Service Tool (MEDIUM PRIORITY)

**File: `gateway/82-odin-routines-database-UNHASHED.md`**

Keep ONLY:
- [ ] Odin database JSON format
- [ ] Access level flags (UDP/GTW in database)
- [ ] Odin script locations
- [ ] Database extraction story

Remove (move to 77):
- [ ] Config ID mappings
- [ ] Gateway config examples
- [ ] Security classifications

**New File: `tools/84-odin-service-tool.md`**

Add:
- [ ] gw-diag command reference (27 commands)
- [ ] Odin Python scripts overview
- [ ] Config read/write API
- [ ] Usage examples
- [ ] Attack scenarios

### Phase 3: Consolidate Cross-References (LOW PRIORITY)

- [ ] Update all docs to reference correct locations
- [ ] Remove duplicate information
- [ ] Update INDEX.md navigation
- [ ] Verify all links work

## Benefits

- **Clearer structure**: Gateway stuff in Gateway section, tool stuff in Tools section
- **No duplication**: Each fact in exactly one place
- **Better navigation**: Easy to find specific info
- **More maintainable**: Updates go to one place

## Status

- [x] Gateway README.md created
- [ ] Phase 1 in progress
- [ ] Phase 2 not started
- [ ] Phase 3 not started

---

*Created: 2026-02-03*
*Priority: Complete Phase 1 first (most impactful)*
