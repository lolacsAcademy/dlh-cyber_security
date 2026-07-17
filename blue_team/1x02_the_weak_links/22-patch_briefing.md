# Patch Briefing — Week of [Board Meeting]

## Three Things We Patch This Week

**1. A hole in our patient records system.** A known flaw lets someone read files off the server that runs our electronic health records, including the passwords for the patient database. It's already being used by attackers against other hospitals right now. If exploited, someone could read or steal patient records directly. Fix: a same-day configuration change, no cost, no downtime.

**2. Our MRI's control computer runs software from 2001 that can never be fixed.** It has three known ways in, all of them already used in real attacks elsewhere, including WannaCry. We can't patch it or replace it this year, but we can lock it down so nothing else on our network can reach it, and it can't reach anything else. Fix: network isolation, roughly $10-30K, deployable within days.

**3. Our infusion pumps still use the factory default password.** Anyone on our network could log into the pumps' management screens. Fix: change every password this week, no cost, a few hours of work.

**If we don't act:** any one of these gives an attacker a real path to patient data, to a device that directly affects patient safety, or to both — and once someone is on the flat network we described three weeks ago, they don't stay contained to one system.

## The Arc

In three weeks, we've gone from mapping every asset and gap we have, to identifying exactly who is likely to attack us and how, to now knowing precisely which of our 34 known weaknesses are live, exploitable and worth fixing first — this week's three items are that work paying off in action, not paperwork.
