# swift

## TODO

### Sections

- [x] `__swift5_entry`
- [x] `__swift5_builtin`
- [x] `__swift5_reflstr`
- [x] `__swift5_fieldmd`
- [x] `__swift5_assocty`
- [x] `__swift5_proto`
- [x] `__swift5_types`
- [x] `__swift5_types2` // the section containing additional type references
- [?] `__swift5_typeref`
- [x] `__swift5_protos`
- [x] `__swift5_capture`
- [ ] `__swift5_replace`
- [ ] `__swift5_replac2`
- [x] `__swift5_acfuncs`
- [ ] `__swift5_mpenum` ?? check Foundation
- [x] `__constg_swiftt`
- [ ] `__textg_swiftm`

### Protocol Conformances

- [ ] parse witness tables *(I got the patterns, but there's data after the description ptr (looks like func ptrs))*

### Type *(Conformances)*

- [ ] add type's protocol conformances to their output *(will require caching/looking up type names etc)*

### Protocols

- [ ] properly represent signature requirements *(I believe if they are key_args they belong in PROT<A: proto, A: proto> etc)*

### Metadata

- [ ] parse all the different type's metatdata

### Demangle *(hard)*

- [ ] pure Go Swift demangler
- [ ] symbolic mangled type algorithm + demangler