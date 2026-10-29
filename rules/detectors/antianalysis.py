from worker.rules.engine import AnalysisCtx, RuleHit


def detect(ctx: AnalysisCtx) -> list[RuleHit]:
    return ctx.group_hits("G_ANTIANALYSIS")
