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
| 2. literature agent | outline | `literature/citation_map.json`, `literature/references.bib` (each entry verified on Semantic Scholar) | next |
| 3. section writing agent | outline, citation map | `latex/paper.tex` | |
| 4. content refinement (AgentReview reviewer, USENIX rubric) | paper | `latex/paper.tex`, `refinement/worklog.json` | |
| 5. plotting / format | outline plotting plan | `latex/figures/` | |

Deadlines (AoE): registration 19/01/2027, paper 26/01/2027, artifacts 29/01/2027.
