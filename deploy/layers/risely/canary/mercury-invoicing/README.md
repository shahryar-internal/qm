# Mercury scheduled invoicing

This module compiles profile-scoped daily, weekly, or monthly billing records into deterministic Mercury invoice candidates. It is provider-free and cannot run the Mercury CLI.

Invoice numbers bind the deployment profile, schedule occurrence, billing-record digest, customer, and destination account. Batches are sorted and explicitly sequential because Mercury exposes one create request per invoice rather than a bulk endpoint.

`prepare_only` always sets `sendEmailOption` to `DontSend`. Mercury cannot later deliver an invoice created this way through the API. `send_after_approval` instead compiles `SendNow`, but remains blocked until an exact one-use approval is durably consumed before the create request.

The prospective CLI contract pins the official Mercury CLI repository and commit, fixes the sandbox or production API host, disables debug and update checks, forbids caller-selected base URLs, keeps the token out of argv and stdin, and exposes no update, cancel, customer, recipient, payment, transfer, or card operation.

An ambiguous create result enters an outcome-unknown hold with retries disabled. Reconciliation must read the exact provider invoice ID when known or match the deterministic invoice number before any terminal transition.

`presentWorkflowArtifact` compiles an actionless `qm.card.v1` envelope for QM's authenticated workflow-artifact renderer. It includes only bounded invoice numbers, amounts, due dates, and states; customer emails, provider customer/account identifiers, CLI stdin, approval controls, and raw billing records are excluded. The exact MIME is `application/vnd.qm.workflow-artifact+json;v=1`.

The CEO profile now declares `mercury.invoices.create` and the Risely Mercury provider owner. This module still has no entry in the executable provider-effect policy catalog; adding that entry requires the exact candidate-to-proposal adapter and independent authority review.

Activation still requires that reviewed provider-effect policy entry, a trusted QM schedule-fire receipt and explicit `activeUntil` disable transition, signed organization/customer/destination-account receipts, trusted billing records, durable reservations, one-use approvals, a sandbox-proven CLI binary and adapter, and authenticated reconciliation receipts.

The contract follows Mercury's [invoicing guide](https://docs.mercury.com/docs/invoicing), [create-invoice reference](https://docs.mercury.com/reference/createinvoice), [sandbox guide](https://docs.mercury.com/docs/using-mercury-sandbox), and the official [Mercury CLI](https://github.com/MercuryTechnologies/mercury-cli) pinned in the source projection.
