// SAM Quant Risk Guard — Tradeify Select 50K technical preparation.
// SIMULATION ONLY. Order submission is disabled in SamQuantStrategy.
// Do not treat this file as Evaluation-passed or live-authorized.
#region Using declarations
using System;
#endregion

namespace NinjaTrader.NinjaScript.Strategies
{
    public static class SamQuantRiskGuard
    {
        public const bool SimulationOnly = true;
        public const bool OrderSubmissionEnabled = false;
        public const bool LiveExecutionAuthorized = false;
        public const decimal StartingBalanceUsd = 50000m;
        public const decimal ProfitTargetUsd = 3000m;
        public const decimal MaxDrawdownUsd = 2000m;
        public const decimal ConsistencyPercent = 40m;
        public const int MaxMiniContracts = 4;
        public const int MaxMicroContracts = 40;
        public const int MinOrderIntervalMs = 2000;
        public const int MaxOrdersPerRollingMinute = 6;

        public static bool IsSimulationAccount(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                return false;
            string name = accountName.Trim();
            return name.StartsWith("Sim", StringComparison.OrdinalIgnoreCase)
                || name.IndexOf("Playback", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("Simulation", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static int MicroEquivalent(bool mini, int quantity)
        {
            int absQty = quantity < 0 ? -quantity : quantity;
            return mini ? absQty * 10 : absQty;
        }

        public static bool ExceedsMaxContracts(bool mini, int projectedQty)
        {
            return MicroEquivalent(mini, projectedQty) > MaxMicroContracts;
        }

        public static bool DrawdownBreached(decimal equity, decimal highWaterMark)
        {
            decimal floorFromStart = StartingBalanceUsd - MaxDrawdownUsd;
            return equity <= floorFromStart || highWaterMark - equity >= MaxDrawdownUsd;
        }

        public static bool ProfitTargetReached(decimal equity)
        {
            return equity >= StartingBalanceUsd + ProfitTargetUsd;
        }

        public static bool ConsistencyBreached(decimal bestDayPnl, decimal totalProfit)
        {
            decimal maxBestAtTarget = ProfitTargetUsd * (ConsistencyPercent / 100m);
            if (bestDayPnl > maxBestAtTarget)
                return true;
            if (totalProfit <= 0m)
                return false;
            return bestDayPnl > totalProfit * (ConsistencyPercent / 100m);
        }

        public static bool SubmissionAllowed(string accountName)
        {
            if (!SimulationOnly)
                return false;
            if (OrderSubmissionEnabled)
                return false;
            if (LiveExecutionAuthorized)
                return false;
            if (!IsSimulationAccount(accountName))
                return false;
            return false;
        }
    }
}
