# Mercury scheduled invoicing

This module compiles profile-scoped daily, weekly, or monthly billing records into deterministic Mercury invoice candidates. It is provider-free and cannot run the Mercury CLI.

Invoice numbers bind the deployment profile, schedule occurrence, billing-record digest, customer, and destination account. Batches are sorted and explicitly sequential because Mercury exposes one create request per invoice rather than a bulk endpoint.

`prepare_only` always sets `sendEmailOption` to `DontSend`. Mercury cannot later deliver an invoice created this way through the API. `send_after_approval` instead compiles `SendNow`, but remains blocked until an exact one-use approval is durably consumed before the create request.

The prospective CLI contract pins Mercury's official v0.11.8 release, target commit, GitHub checksum asset, Linux/amd64 archive, and extracted static-binary digests. Both the official macOS/arm64 and Linux/amd64 binaries passed an isolated loopback test proving the compiled stdin becomes exactly one `POST /api/v1/ar/invoices` request. The test used only a test token and never contacted Mercury. The contract also fixes the sandbox or production API host, disables debug and update checks, forbids caller-selected base URLs, keeps the token out of argv and stdin, and exposes no update, cancel, customer, recipient, payment, transfer, or card operation.

An ambiguous create result enters an outcome-unknown hold with retries disabled. Reconciliation must read the exact provider invoice ID when known or match the deterministic invoice number before any terminal transition.

`presentWorkflowArtifact` compiles an actionless `qm.card.v1` envelope for QM's authenticated workflow-artifact renderer. It includes only bounded invoice numbers, amounts, due dates, and states; customer emails, provider customer/account identifiers, CLI stdin, approval controls, and raw billing records are excluded. The exact MIME is `application/vnd.qm.workflow-artifact+json;v=1`.

The CEO profile declares `mercury.invoices.create` and the Risely Mercury provider owner. The program fixes `executionAvailable=false`; its candidates and CLI plans remain provider-free, and no candidate-to-proposal adapter, executable provider-effect catalog entry, or production adapter exists. Execution cannot become available until trusted schedule-fire receipt and catalog authority are implemented and independently reviewed.

Activation still requires a reviewed provider-effect catalog entry and production adapter, trusted QM schedule-fire lineage with an explicit `activeUntil` disable transition, durable effect reservation and one-use approval consumption, signed organization/customer/destination-account identities and trusted billing receipts, a sandbox-credential acceptance run, immutable packaging of only the pinned binary with reviewed artifact provenance, authenticated provider reconciliation, and authenticated workflow-artifact UI acceptance.

The contract follows Mercury's [invoicing guide](https://docs.mercury.com/docs/invoicing), [create-invoice reference](https://docs.mercury.com/reference/createinvoice), [sandbox guide](https://docs.mercury.com/docs/using-mercury-sandbox), and the official [Mercury CLI](https://github.com/MercuryTechnologies/mercury-cli) pinned in the source projection.
