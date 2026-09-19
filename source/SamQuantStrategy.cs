// SAM Quant native NinjaScript strategy adapter.
// TECHNICAL PREPARATION ONLY.
// Dual-MA core computes an intended action. OrderSubmissionEnabled is false.
// This strategy must not send Evaluation orders.
#region Using declarations
using System;
using NinjaTrader.Cbi;
using NinjaTrader.NinjaScript;
#endregion

namespace NinjaTrader.NinjaScript.Strategies
{
    public class SamQuantStrategy : Strategy
    {
        private const bool SimulationOnly = SamQuantRiskGuard.SimulationOnly;
        private const bool OrderSubmissionEnabled = SamQuantRiskGuard.OrderSubmissionEnabled;
        private const bool LiveExecutionAuthorized = SamQuantRiskGuard.LiveExecutionAuthorized;
        private const int ShortWindow = 3;
        private const int LongWindow = 5;
        private const int DefaultQuantity = 1;
        private decimal highWaterMark = SamQuantRiskGuard.StartingBalanceUsd;

        protected override void OnStateChange()
        {
            if (State == State.SetDefaults)
            {
                Description = "SAM Quant Tradeify 50K dual-MA core. Orders disabled.";
                Name = "SamQuantStrategy";
                Calculate = Calculate.OnBarClose;
                IsInstantiatedOnEachOptimizationIteration = false;
            }
        }

        protected override void OnBarUpdate()
        {
            if (!SimulationOnly)
                return;
            if (LiveExecutionAuthorized)
                return;
            if (OrderSubmissionEnabled)
                return;
            if (Account == null || !SamQuantRiskGuard.IsSimulationAccount(Account.Name))
                return;

            decimal equity = SamQuantRiskGuard.StartingBalanceUsd;
            try
            {
                equity = Convert.ToDecimal(
                    Account.Get(AccountItem.NetLiquidation, Currency.UsDollar));
            }
            catch (Exception)
            {
                Print("SAM Quant capital-limit fail-closed intended=HOLD unknown-equity");
                return;
            }
            if (equity > highWaterMark)
                highWaterMark = equity;
            if (SamQuantRiskGuard.DrawdownBreached(equity, highWaterMark)
                || SamQuantRiskGuard.ProfitTargetReached(equity))
            {
                string halt = Position.MarketPosition == MarketPosition.Flat ? "HOLD" : "FLATTEN";
                Print("SAM Quant capital-limit fail-closed intended=" + halt);
                return;
            }

            if (CurrentBar < LongWindow)
                return;

            double currShort = 0;
            double currLong = 0;
            double prevShort = 0;
            double prevLong = 0;
            for (int i = 0; i < ShortWindow; i++)
                currShort += Close[i];
            currShort /= ShortWindow;
            for (int i = 0; i < LongWindow; i++)
                currLong += Close[i];
            currLong /= LongWindow;
            for (int i = 1; i <= ShortWindow; i++)
                prevShort += Close[i];
            prevShort /= ShortWindow;
            for (int i = 1; i <= LongWindow; i++)
                prevLong += Close[i];
            prevLong /= LongWindow;

            string intended = "HOLD";
            if (prevShort <= prevLong && currShort > currLong)
            {
                if (Position.MarketPosition == MarketPosition.Short)
                    intended = "FLATTEN";
                else if (Position.MarketPosition == MarketPosition.Flat)
                    intended = "LONG";
            }
            else if (prevShort >= prevLong && currShort < currLong)
            {
                if (Position.MarketPosition == MarketPosition.Long)
                    intended = "FLATTEN";
                else if (Position.MarketPosition == MarketPosition.Flat)
                    intended = "SHORT";
            }
            Print("SAM Quant intended=" + intended + " qty=" + DefaultQuantity);
            // Native order APIs are intentionally not called.
        }

        protected override void OnOrderUpdate(
            Order order,
            double limitPrice,
            double stopPrice,
            int quantity,
            int filled,
            double averageFillPrice,
            OrderState orderState,
            DateTime time,
            ErrorCode error,
            string comment)
        {
            // No-op: this preparation build does not manage real or Evaluation tickets.
        }
    }
}
