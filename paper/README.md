# Paper workspace (USENIX Security '27, cycle 2)

Method: the PaperOrchestra pipeline (google-research/paper-orchestra, cloned outside the project at
`~/Downloads/paper-orchestra`), with Claude acting as each agent instead of the Gemini/OpenAI calls of its code (owner
decision 17/11: free tools only, the unpublished paper does not leave the machine). The repo's prompts are followed
step by step; two of its rules are overridden (see `templates/usenix-security/guidelines.md`, last section).

| PaperOrchestra step | Input | Output here | State |
|---|---|---|---|
| raw materials | thesis, receipts | `raw_materials/idea_dense.md`, `raw_materials/experimental_log.md`, `raw_materials/figures/info.json` | done 17/11 (v6, LID-DS 2019 PENDING) |
| template + guidelines | USENIX Security '27 CFP and template | `templates/usenix-security/` | done 17/11 |
| 1. outline agent | the above | `outline.json` | done 17/11 |
| 2. literature agent | outline | `literature/citation_map.json` (Semantic Scholar; Crossref by DOI when S2 has no record) | done 18/11: 53 checked, 47 papers verified; the submitted `references.bib` will be generated from the verified metadata, never edited by hand (an author name was nearly mistyped on 17/11) |
| 3. section writing agent | outline, citation map | `latex/paper.tex`, `latex/sections/*.tex` | 17/11: background, design, implementation, evaluation written (v6 and LID-DS 2019 parts PENDING); 18/11: introduction, related work, discussion, conclusion, appendices written; 12 pages, body about 9.5 of 13 |
| 4. content refinement (AgentReview reviewer, USENIX rubric) | paper | `latex/paper.tex`, `refinement/worklog.json` | |
| 5. plotting / format | outline plotting plan | `latex/figures/` | |

Deadlines (AoE): registration 19/01/2027, paper 26/01/2027, artifacts 29/01/2027.

Build (official template needs pdfTeX; TinyTeX in `~/.TinyTeX`, binaries in `~/.local/bin`):
`cd paper/latex && pdflatex paper && bibtex paper && pdflatex paper && pdflatex paper`

Bibliography: `python3 paper/tools/make_bib.py --map paper/literature/citation_map.json --thesis-bib thesis/references.bib --software paper/literature/software.bib --sections paper/latex/sections --output paper/latex/references.bib --crossref-cache paper/literature/crossref_cache.json` (titles and authors from the verified record; year, venue and pages from Crossref by DOI; books and DOI-less entries from the thesis entry; a cited key that is not verified stops the build).
