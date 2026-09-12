<!--
Thanks for contributing to ModularCA. The checklist is short on purpose; the CLA line is the
one that will block a merge, and the security question is the one most likely to change how a
change gets reviewed.
-->

## What changed, and why

<!-- The "why" matters more than the "what" here — the diff already says what. If this fixes
     something that was silently wrong, describe what it did before. -->

## Related issue

<!-- Link it, or say "none". -->

## Checklist

- [ ] I have signed the [CLA](../CLA.md) and my handle is in
      [CLA-SIGNATURES.md](../CLA-SIGNATURES.md) *(required — a CI check enforces this)*
- [ ] Commits are signed off (`git commit -s`)
- [ ] `dotnet build ModularCA.sln` succeeds with no new warnings
- [ ] `dotnet test` passes
- [ ] For TypeScript changes: `npx tsc -b` passes, and `cd tests/modularca.web.tests && npm test`
- [ ] New behaviour has a test that fails without the change

## Security impact

<!-- Answer even if it is "none". This is a certificate authority: changes to issuance,
     validation, authentication, authorization, key handling, revocation or audit get a closer
     read, and saying so up front is faster than having it discovered in review.

     If this touches how a certificate is built or validated, say which RFC requirement applies.
-->

## Anything you are unsure about

<!-- Optional, and genuinely useful. Flagging the part you are least confident in gets you a
     better review than presenting it as finished. -->
