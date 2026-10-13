# Create glossary entries and guides

Open **Glossary → New glossary entry** or **Guides → New guide**. Both use the same editor and saved catalog. To reuse existing content, open its detail view and choose **Use as template**; this creates a separate entry. **Edit local copy** saves an installation-specific revision of shipped content, keeping its existing links intact. After the first save, the action is labeled **Edit**.

1. Choose the content type, section and category. Glossary sections cover artifacts, registry keys, persistence locations and Windows events; guides can be hypothesis driven or artifact driven. The section becomes fixed after saving, so use a template to create a different type.
2. For a glossary entry, fill in the labeled fields. Artifact entries support operating systems, interpretation, corroboration, evidence locations and key fields. Enter lists one item per line. Expand **Database and event details** to add grouped database/table/timestamp rows or related event IDs, providers and meanings.
3. For a guide, enter its title, summary and search keywords, then fill in the provided sections. Select text to apply headings, bold, italic, lists or code blocks. **Add section**, **Add table** and **Insert web link** extend the body. Pasted text keeps the editor's formatting consistent; starting from an existing guide preserves its full section structure.
4. Choose **Insert glossary link**, search for any saved entry, and optionally change the visible link text. Save a new glossary entry first, then select it here; no restart or source-code changes are needed. Links use stable entry IDs, so later definition edits update their hover and keyboard-focus tooltips. Clicking a link opens its reference in the glossary sidebar.
5. Choose **Preview** to check the same rendering used by the library, then **Save content** and **View saved content**. Previews do not save your draft. Saved entries participate in search, category views and sidebars. Other open tabs refresh after saves or when brought into focus. If another editor saved first, your save is rejected with a conflict message so it cannot overwrite that revision silently; preserve your draft before reloading.

Custom content and local revisions are stored in the workstation's SIFTed database (`SIFTED_DATABASE_PATH`, normally `data/sifted.sqlite3`). Keep the same database when upgrading or restarting. Stop SIFTed before making a filesystem backup of the database, or use SQLite's backup facility while it is running. The shipped catalog is in `content/builtin.json`; normal authoring does not require editing it.

![Guide editor with formatting controls and a tooltip for a newly created Browser collection notes entry](screenshots/guide-authoring.png)

## DFIR guide writing guidelines

Concise, Coherent, and Quietly Instructive

These guidelines exist to keep DFIR guides useful under pressure.
They are not meant to be encyclopedic. They are meant to shape judgment
without overwhelming the analyst.

If a guide feels like a wiki, it has already failed.

==================================================
CORE PRINCIPLE
==================================================

A good DFIR guide:
• Narrows thinking without narrowing curiosity
• Reduces uncertainty without promising certainty
• Trains analysts through repetition, not instruction

Conciseness is not minimalism.
Conciseness is *selectivity with intent*.

--------------------------------------------------

==================================================
1. ONE HYPOTHESIS ONLY
==================================================

RIGHT
• Each guide addresses exactly one testable hypothesis
• The hypothesis can be disproven safely
• Language remains conditional throughout

WRONG
• Multiple overlapping hypotheses
• “Catch-all” investigations
• Implicit assumptions of compromise

Guides should constrain scope, not expand it.

--------------------------------------------------

==================================================
2. FEWER QUESTIONS, BETTER QUESTIONS
==================================================

RIGHT
• 3–5 key questions maximum
• Each question changes investigative direction
• At least one question challenges the hypothesis

WRONG
• Long question lists
• Questions that restate the hypothesis
• Questions that can only be answered by running tools

If a question does not influence a decision, it does not belong.

--------------------------------------------------

==================================================
3. ARTIFACT CATEGORIES, NOT EXHAUSTIVE LISTS
==================================================

RIGHT
• Evidence grouped by artifact behavior
• Examples are illustrative, not complete
• Focus on *why* an artifact matters, not where it lives

WRONG
• Full artifact inventories
• Registry key dumps
• Location-heavy explanations

Guides should teach recognition, not memorization.

--------------------------------------------------

==================================================
4. INTENTIONAL OMISSIONS ARE A FEATURE
==================================================

RIGHT
• Leaves room for analyst judgment
• Assumes baseline DFIR literacy
• Avoids repeating universally known fundamentals

WRONG
• Over-explaining basic concepts
• Defensive writing to cover every edge case
• Teaching to the lowest common denominator

Trust the analyst to think.

--------------------------------------------------

==================================================
5. ONE SENTENCE PER INSIGHT
==================================================

RIGHT
• Each section communicates a single idea
• Sentences are dense but readable
• Redundancy is eliminated

WRONG
• Paragraphs explaining one point
• Multiple insights per sentence
• Repeating the same warning in different words

If it takes a paragraph, it’s probably two ideas.

--------------------------------------------------

==================================================
6. LIMITATIONS ARE NON-NEGOTIABLE
==================================================

RIGHT
• Explicitly states what evidence does not prove
• One or two constraints per section
• Uses calm, factual language

WRONG
• No mention of uncertainty
• Overuse of caveats
• Legal disclaimers masquerading as insight

One good limitation teaches more than five confirmations.

--------------------------------------------------

==================================================
7. PITFALLS OVER PROCEDURES
==================================================

RIGHT
• Calls out cognitive traps
• Focuses on how analysts misinterpret data
• Derived from real investigations

WRONG
• Step-by-step instructions
• Tool usage guidance
• “If this, then that” recipes

Procedures expire.
Mistakes repeat.

--------------------------------------------------

==================================================
8. CORROBORATION OVER COMPLETENESS
==================================================

RIGHT
• Encourages multiple independent signals
• Avoids “collect everything” mentality
• Emphasizes confidence-building

WRONG
• Exhaustive data collection
• Volume-based confidence
• Treating absence as proof

Enough evidence is better than all evidence.

--------------------------------------------------

==================================================
9. BUILT-IN EXIT CONDITIONS
==================================================

RIGHT
• Clear guidance on when to reassess
• Normalizes pivoting
• Prevents infinite investigation

WRONG
• No stopping point
• Endless artifact review
• Conflating effort with correctness

Stopping is a skill.

--------------------------------------------------

==================================================
10. WRITE FOR THE TIRED ANALYST
==================================================

RIGHT
• Scannable structure
• No buried critical insight
• Calm, precise tone

WRONG
• Dense prose
• Hidden warnings
• Dramatic or urgent language

If it can’t be used at 03:00, it doesn’t belong.

--------------------------------------------------

==================================================
GUIDE STRUCTURE
==================================================

Every hypothesis-driven guide uses three logical groups:

FRAMING
• The hypothesis: One or two sentences. What you suspect and what
  you're trying to prove or disprove.
• Key questions: 3–5 questions that guide thinking. At least one
  must challenge the hypothesis.

EVIDENCE
• Artifact sections grouped by behavior, not tool or location.
• Use "may indicate" language—never certainty.
• Link artifacts using artifact-link spans for glossary integration.
• Keep lists illustrative, not exhaustive.

ANALYSIS
• Corroboration: What independent signals increase confidence?
• Pitfalls: Cognitive traps specific to this hypothesis.
• Limitations: What this evidence does NOT prove.
• When to stop: Clear exit conditions and pivot guidance.

--------------------------------------------------

==================================================
VISUAL STYLING
==================================================

Section labels use colored uppercase text:
• Standard labels: Pink (--neon-pink)
• Warning labels (Pitfalls, Limitations): Amber (--neon-amber)

Group headers use dim, small uppercase text to provide context
without competing with section content.

Artifact links appear in teal and open the glossary sidebar.
Do not duplicate this color for section labels.

--------------------------------------------------

==================================================
HTML TEMPLATE
==================================================

<div class="guide-body">
  <div class="guide-group">
    <div class="guide-group-header">Framing</div>
    <div class="guide-detail-section">
      <div class="guide-detail-label">The hypothesis</div>
      <p class="guide-detail-text">[One or two sentences]</p>
    </div>
    <div class="guide-detail-section">
      <div class="guide-detail-label">Key questions</div>
      <ul class="guide-detail-list">
        <li>[Question that guides thinking]</li>
        <li>[Question that challenges hypothesis]</li>
      </ul>
    </div>
  </div>
  <div class="guide-group">
    <div class="guide-group-header">Evidence</div>
    <div class="guide-detail-section">
      <div class="guide-detail-label">[Artifact category]</div>
      <ul class="guide-detail-list">
        <li><span class="artifact-link" data-artifact="[id]">[Name]</span> [context].</li>
      </ul>
    </div>
    <!-- Additional artifact sections as needed -->
  </div>
  <div class="guide-group">
    <div class="guide-group-header">Analysis</div>
    <div class="guide-detail-section">
      <div class="guide-detail-label">Corroboration</div>
      <ul class="guide-detail-list">
        <li>[Independent signal that increases confidence]</li>
      </ul>
    </div>
    <div class="guide-detail-section">
      <div class="guide-detail-label warning">Pitfalls</div>
      <ul class="guide-detail-list">
        <li>[Cognitive trap to avoid]</li>
      </ul>
    </div>
    <div class="guide-detail-section">
      <div class="guide-detail-label warning">Limitations</div>
      <ul class="guide-detail-list">
        <li>[What this evidence does NOT prove]</li>
      </ul>
    </div>
    <div class="guide-detail-section">
      <div class="guide-detail-label">When to stop</div>
      <p class="guide-detail-text">[Exit conditions and pivot guidance]</p>
    </div>
  </div>
</div>

--------------------------------------------------

==================================================
FINAL CHECK
==================================================

Before publishing, ask:

☐ Can this guide be read in under five minutes?
☐ Does every section change how the analyst thinks?
☐ Would this still be safe if the hypothesis is wrong?
☐ Are the three groups (Framing, Evidence, Analysis) present?
☐ Does at least one key question challenge the hypothesis?
☐ Are pitfalls and limitations included?

If any answer is "no," revise.

==================================================
CLOSING PRINCIPLE
==================================================

The goal is not to teach everything.
The goal is to teach the *shape of good thinking*.

That shape, repeated enough times,
becomes instinct.

