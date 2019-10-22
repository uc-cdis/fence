# dbGaP Information (as understood by Gen3)

The [Database for Genotypes and Phenotypes (dbGaP)](https://www.ncbi.nlm.nih.gov/gap/) is used to "archive and distribute the data and results from studies that have investigated the interaction of genotype and phenotype in Humans".

> NOTE: For official details about dbGaP please visit the official site/documentation.

The largest unit of data that can be submitted to dbGaP is a *Study*. Studies can have sub-studies. Each study is identified by a unique study number (AKA phsid AKA study accession) and additional information (like version), which may look something like `phs001826.v1.p1.c1`. The `.` delimites various pieces of information.

* `phs001826`: unique study identifier
* `v1`: data version
* `p1`: participant set version
* `c1`: consent group version

The combination of these fields is known as a *dbGaP Accession Number*.

More information about this can be found in [this NCBI article](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC2031016/).

## Authorization

Fence is capable of syncing user access information from dbGaP's *Telemetry Files* (AKA study whitelists). These are typically provided in an SFTP server as CSV's or TXT's. You can see an example of the format in the Fence unit tests (`/tests/dbgap_sync`).

A single *Telemetry File* represents the access allowed for a given dbGaP study accession. The file will contain rows of eRA Commons user IDs and other information. Fence is able to parse all *Telemetry Files* in an SFTP server (given credentials for the SFTP server).

## Consent Groups

Fence contains a configuration for whether or not to parse consent codes (at the time of writing, it is `parse_consent_code` in the `dbGaP` block).

> NOTE: Reference the `config-default.yaml` for current configuration options and further details.

When parsing consent codes, the authorization resources a user is given access to will be in the form `study_id.consent_group` (ex: `phs001826.c2`).

### Consent Group `c999` Handling

The consent group `c999` is interpretted as meaning the user should implicitly have access
to **all** available consent groups within the study. It can additionally be interpretted
as providing access to that study's "exchange area" (in addition to the parent study's
"common exchange area").

Fence will consolidate all known consents for a given study and then provide any user
with `c999` access to all those consents (including `.c999` explicitly, to represent
that study's exchange area).

Fence allows configuring whether or not you want to handle the "common exchange area" logic
mentioned above (at the time of writing, it is `enable_common_exchange_area_access` in the `dbGaP` block).

When turned on, you can provide a list of study identifiers (ex: `phs000123`, `phs000456`) and the resource you want to represent their parent study's common exchange area (ex: `123_and_456_common_exchange_area`) in Fence's configuration file (at the time of writing, it is `study_common_exchange_areas` in the `dbGaP` block).

> NOTE: Again, please see the `config-default.yaml` for more information about available configurations.

For example, `c999` would be handled slightly differently based on configuration. Below, assume a user has access to `c999` consent group:

|| **Consent Cfg == True**  | **Consent Codes Cfg == False** |
|---| ------------- | ------------- |
| **Common Exchange Cfg == True** | access to: common exchange area (if phsid in cfg mapping) + study-specifc exchange area + all consent codes  | c999 ignored, access to phsid w/o consent |
| **Common Exchange Cfg == False** | access to: study-specifc exchange area + all consent codes | c999 ignored, access to phsid w/o consent |

So the user access granted in a situation with `phs000123.c999` (assuming there exists a
`phs000123.c1` and `phs000123.c2`):

|| **Consent Cfg == True**  | **Consent Codes Cfg == False** |
|---| ------------- | ------------- |
| **Common Exchange Cfg == True** | `test_common_exchange_area` + `phs000123.c999` + `phs000123.c1`, `phs000123.c2` | `phs000123`
| **Common Exchange Cfg == False** | `phs000123.c999` + `phs000123.c1`, `phs000123.c2` | `phs000123` |

> NOTE: On the resource level, `phs000123.c999` should refer to resources that exist in that study's specific exchange area. Resources in the parent's common exchange area should be controlled via `test_common_exchange_area`.

## Version Updates

A study can be updated and at that time the patients and consent groups may change and the version number `v1` would get bumped up. At the moment, Fence does not handle these versions, so authorization is effectively either study level, or study+consent level.