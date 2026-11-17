# USENIX Security '27 Paper Writing Guidelines

Source: USENIX Security '27 call for papers (`sec27_cfp-070826.pdf`, fetched 17/11/2026) and the official template
`usenixsecurity2027_latex_templates.zip` (`usenix.sty`, `usenixsecurity2027.tex`). Target: cycle 2 (registration with fixed
title, authors, abstract and topics due 19/01/2027; paper due 26/01/2027; artifacts due 29/01/2027, all AoE).

## General Setup
* **Document class:** `\documentclass[letterpaper,twocolumn,10pt]{article}` with `\usepackage{usenix}`.
* U.S. letter, two columns, 10-point Times Roman on 12-point leading, text block 7" x 9".
* Do not change fonts, margins or spacing; no negative `\vspace`, no squeezing of floats. Page limits are met by editing content only.
* Bibliography style: `plain` (as in the template); every entry must exist and be correct: invented references,
  wrong authors, invented claims or falsified results are academic misconduct and lead to desk rejection.

## Length
* **Body:** at most **13 pages**, excluding references and appendices.
* **Submission:** unlimited appendices and references, but reviewers are not required to read appendices.
* **Camera-ready:** at most 20 pages in total, including the Ethical Considerations and Open Science appendices.

## Mandatory and recommended parts
* **Abstract:** one paragraph, not more than 200 words, preferably about 150.
* **Open Science appendix (mandatory at submission):** list every artifact (code, data, protocols, receipts) and how to
  access it through anonymous links without tracking (e.g. anonymous.4open.science); explain anything that cannot be shared.
* **Ethics appendix (recommended):** stakeholders, harms and mitigations of the research and of its publication. For this
  work: the testbed is the authors' own cluster; attacks are self-written fixtures (no CVE exploit, no vulnerable image);
  public datasets (LID-DS 2021/2019, CB-DS) are used under their licences; no human subjects.

## Anonymity (double-blind)
* No author names or affiliations on the title page (use "Anonymous Submission").
* Refer to own prior work in the third person; do not name the lab, the cluster's organisation or internal hostnames.
* Remove identifying paths, usernames, commit URLs and repository names; artifact links must be anonymous.

## Use of AI
* Permitted; the human authors are responsible for every claim, number, piece of code and reference, and must have reviewed
  all AI-generated content as if they had written it.

## Topic
* Systems security: intrusion and anomaly detection, cloud/container security. Machine learning is a tool here; the paper
  must read as a systems security contribution (see "Submitting ML Work to USENIX Security").

## Conventions for this paper (project rules, override the PaperOrchestra defaults)
* Every number comes from a committed receipt under `validation-evidence/` (the experimental log quotes the receipt path).
* Negative results and limitations are stated, not hidden (the PaperOrchestra refinement prompt says the opposite; it is
  overridden).
* Results not yet measured are marked `PENDING` in the experimental log and never filled in by guess.
