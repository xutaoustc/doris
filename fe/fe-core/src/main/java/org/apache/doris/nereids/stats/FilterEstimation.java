// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.nereids.stats;

import org.apache.doris.common.Id;
import org.apache.doris.nereids.stats.FilterEstimation.EstimationContext;
import org.apache.doris.nereids.trees.expressions.And;
import org.apache.doris.nereids.trees.expressions.ComparisonPredicate;
import org.apache.doris.nereids.trees.expressions.CompoundPredicate;
import org.apache.doris.nereids.trees.expressions.EqualTo;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.GreaterThan;
import org.apache.doris.nereids.trees.expressions.GreaterThanEqual;
import org.apache.doris.nereids.trees.expressions.InPredicate;
import org.apache.doris.nereids.trees.expressions.LessThan;
import org.apache.doris.nereids.trees.expressions.LessThanEqual;
import org.apache.doris.nereids.trees.expressions.Not;
import org.apache.doris.nereids.trees.expressions.Or;
import org.apache.doris.nereids.trees.expressions.Slot;
import org.apache.doris.nereids.trees.expressions.SlotReference;
import org.apache.doris.nereids.trees.expressions.literal.Literal;
import org.apache.doris.nereids.trees.expressions.visitor.ExpressionVisitor;
import org.apache.doris.statistics.ColumnStatistic;
import org.apache.doris.statistics.ColumnStatisticBuilder;
import org.apache.doris.statistics.StatsDeriveResult;

import com.google.common.base.Preconditions;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Calculate selectivity of expression that produces boolean value.
 * TODO: Should consider the distribution of data.
 */
public class FilterEstimation extends ExpressionVisitor<StatsDeriveResult, EstimationContext> {
    public static final double DEFAULT_INEQUALITY_COMPARISON_SELECTIVITY = 0.8;

    public static final double DEFAULT_EQUALITY_COMPARISON_SELECTIVITY = 0.1;

    private final StatsDeriveResult inputStats;

    public FilterEstimation(StatsDeriveResult inputStats) {
        Preconditions.checkNotNull(inputStats);
        this.inputStats = inputStats;
    }

    /**
     * This method will update the stats according to the selectivity.
     */
    public StatsDeriveResult estimate(Expression expression) {
        // For a comparison predicate, only when it's left side is a slot and right side is a literal, we would
        // consider is a valid predicate.
        return calculate(expression);
    }

    private StatsDeriveResult calculate(Expression expression) {
        return expression.accept(this, null);
    }

    @Override
    public StatsDeriveResult visit(Expression expr, EstimationContext context) {
        return new StatsDeriveResult(inputStats).updateBySelectivity(DEFAULT_INEQUALITY_COMPARISON_SELECTIVITY);
    }

    @Override
    public StatsDeriveResult visitCompoundPredicate(CompoundPredicate predicate, EstimationContext context) {
        Expression leftExpr = predicate.child(0);
        Expression rightExpr = predicate.child(1);
        StatsDeriveResult leftStats = leftExpr.accept(this, null);
        if (predicate instanceof And) {
            return rightExpr.accept(new FilterEstimation(leftStats), null);
        } else if (predicate instanceof Or) {
            StatsDeriveResult rightStats = rightExpr.accept(this, null);
            StatsDeriveResult andStats = rightExpr.accept(new FilterEstimation(leftStats), null);
            double rowCount = leftStats.getRowCount() + rightStats.getRowCount() - andStats.getRowCount();
            StatsDeriveResult orStats = inputStats.updateRowCount(rowCount);
            for (Map.Entry<Id, ColumnStatistic> entry : leftStats.getSlotIdToColumnStats().entrySet()) {
                ColumnStatistic leftColStats = entry.getValue();
                ColumnStatistic rightColStats = rightStats.getColumnStatsBySlotId(entry.getKey());
                ColumnStatisticBuilder estimatedColStatsBuilder = new ColumnStatisticBuilder(leftColStats);
                if (leftColStats.minValue <= rightColStats.minValue) {
                    estimatedColStatsBuilder.setMinValue(leftColStats.minValue);
                    estimatedColStatsBuilder.setMinExpr(leftColStats.minExpr);
                } else {
                    estimatedColStatsBuilder.setMinValue(rightColStats.minValue);
                    estimatedColStatsBuilder.setMinExpr(rightColStats.minExpr);
                }
                if (leftColStats.maxValue >= rightColStats.maxValue) {
                    estimatedColStatsBuilder.setMaxValue(leftColStats.maxValue);
                    estimatedColStatsBuilder.setMaxExpr(leftColStats.maxExpr);
                } else {
                    estimatedColStatsBuilder.setMaxValue(rightColStats.maxValue);
                    estimatedColStatsBuilder.setMaxExpr(rightColStats.maxExpr);
                }
                orStats.addColumnStats(entry.getKey(), estimatedColStatsBuilder.build());
            }
            return orStats;
        }
        throw new RuntimeException(String.format("Unexpected predicate type: %s", predicate.toSql()));
    }

    @Override
    public StatsDeriveResult visitComparisonPredicate(ComparisonPredicate cp, EstimationContext context) {
        boolean isNot = (context != null) && context.isNot;
        Expression left = cp.left();
        Expression right = cp.right();
        ColumnStatistic statsForLeft = ExpressionEstimation.estimate(left, inputStats);
        ColumnStatistic statsForRight = ExpressionEstimation.estimate(right, inputStats);
        ColumnStatisticBuilder leftBuilder = new ColumnStatisticBuilder(statsForLeft);
        double selectivity;
        if (!(left instanceof Literal) && !(right instanceof Literal)) {
            selectivity = calculateWhenBothChildIsColumn(cp, statsForLeft, statsForRight);
        } else {
            // For literal, it's max min is same value.
            selectivity = updateLeftStatsWhenRightChildIsLiteral(cp,
                    leftBuilder,
                    statsForRight.maxValue,
                    isNot);
        }
        StatsDeriveResult outputStats = new StatsDeriveResult(inputStats);
        //TODO: we take the assumption that func(A) and A have the same stats.

        if (left.getInputSlots().size() == 1) {
            Slot leftSlot = left.getInputSlots().iterator().next();
            outputStats.addColumnStats(leftSlot.getExprId(), leftBuilder.build());
        }
        return outputStats.updateBySelectivity(selectivity,
                cp.getInputSlots().stream().map(Slot::getExprId).collect(Collectors.toSet()));
    }

    private double updateLessThan(ColumnStatisticBuilder statsForLeft, double val,
            double min, double max, double ndv) {
        double selectivity = 1.0;
        if (val <= min) {
            statsForLeft.setMaxValue(val);
            statsForLeft.setMinValue(0);
            statsForLeft.setNdv(0);
            selectivity = 0.0;
        } else if (val > max) {
            selectivity = 1.0;
        } else if (val == max) {
            selectivity = 1.0 - 1.0 / ndv;
        } else {
            statsForLeft.setMaxValue(val);
            selectivity = (val - min) / (max - min);
            statsForLeft.setNdv(selectivity * statsForLeft.getNdv());
        }
        return selectivity;
    }

    private double updateLessThanEqual(ColumnStatisticBuilder statsForLeft, double val,
            double min, double max, double ndv) {
        double selectivity = 1.0;
        if (val < min) {
            statsForLeft.setMaxValue(val);
            statsForLeft.setMinValue(val);
            selectivity = 0.0;
        } else if (val == min) {
            statsForLeft.setMaxValue(val);
            selectivity = 1.0 / ndv;
        } else if (val >= max) {
            selectivity = 1.0;
        } else {
            statsForLeft.setMaxValue(val);
            selectivity = (val - min) / (max - min);
            statsForLeft.setNdv(selectivity * statsForLeft.getNdv());
        }
        return selectivity;
    }

    private double updateGreaterThan(ColumnStatisticBuilder statsForLeft, double val,
            double min, double max, double ndv) {
        double selectivity = 1.0;
        if (val >= max) {
            statsForLeft.setMaxValue(val);
            statsForLeft.setMinValue(val);
            statsForLeft.setNdv(0);
            selectivity = 0.0;
        } else if (val == min) {
            selectivity = 1.0 - 1.0 / ndv;
        } else if (val < min) {
            selectivity = 1.0;
        } else {
            statsForLeft.setMinValue(val);
            selectivity = (max - val) / (max - min);
            statsForLeft.setNdv(selectivity * statsForLeft.getNdv());
        }
        return selectivity;
    }

    private double updateGreaterThanEqual(ColumnStatisticBuilder statsForLeft, double val,
            double min, double max, double ndv) {
        double selectivity = 1.0;
        if (val > max) {
            statsForLeft.setMinValue(val);
            statsForLeft.setMaxValue(val);
            selectivity = 0.0;
        } else if (val == max) {
            statsForLeft.setMinValue(val);
            statsForLeft.setMaxValue(val);
            selectivity = 1.0 / ndv;
        } else if (val <= min) {
            selectivity = 1.0;
        } else {
            statsForLeft.setMinValue(val);
            selectivity = (max - val) / (max - min);
            statsForLeft.setNdv(selectivity * statsForLeft.getNdv());
        }
        return selectivity;
    }

    private double updateLeftStatsWhenRightChildIsLiteral(ComparisonPredicate cp,
            ColumnStatisticBuilder statsForLeft, double val, boolean isNot) {
        if (statsForLeft.isBuildOnUnknown()) {
            return 1.0;
        }
        double selectivity = 1.0;
        double ndv = statsForLeft.getNdv();
        double max = statsForLeft.getMaxValue();
        double min = statsForLeft.getMinValue();
        if (cp instanceof EqualTo) {
            if (!isNot) {
                statsForLeft.setNdv(1);
                statsForLeft.setMaxValue(val);
                statsForLeft.setMinValue(val);
                if (val > max || val < min) {
                    selectivity = 0.0;
                } else {
                    selectivity = 1.0 / ndv;
                }
            } else {
                if (val <= max && val >= min) {
                    selectivity = 1 - DEFAULT_EQUALITY_COMPARISON_SELECTIVITY;
                }
            }
        } else if (cp instanceof LessThan) {
            if (isNot) {
                selectivity = updateGreaterThanEqual(statsForLeft, val, min, max, ndv);
            } else {
                selectivity = updateLessThan(statsForLeft, val, min, max, ndv);
            }
        } else if (cp instanceof LessThanEqual) {
            if (isNot) {
                selectivity = updateGreaterThan(statsForLeft, val, min, max, ndv);
            } else {
                selectivity = updateLessThanEqual(statsForLeft, val, min, max, ndv);
            }
        } else if (cp instanceof GreaterThan) {
            if (isNot) {
                selectivity = updateLessThanEqual(statsForLeft, val, min, max, ndv);
            } else {
                selectivity = updateGreaterThan(statsForLeft, val, min, max, ndv);
            }
        } else if (cp instanceof GreaterThanEqual) {
            if (isNot) {
                selectivity = updateLessThan(statsForLeft, val, min, max, ndv);
            } else {
                selectivity = updateGreaterThanEqual(statsForLeft, val, min, max, ndv);
            }
        } else {
            throw new RuntimeException(String.format("Unexpected expression : %s", cp.toSql()));
        }
        return selectivity;

    }

    private double calculateWhenRightChildIsLiteral(ComparisonPredicate cp,
            ColumnStatistic statsForLeft, double val) {
        double ndv = statsForLeft.ndv;
        double max = statsForLeft.maxValue;
        double min = statsForLeft.minValue;
        if (cp instanceof EqualTo) {
            if (val > max || val < min) {
                return 0.0;
            }
            return 1.0 / ndv;
        }
        if (cp instanceof LessThan) {
            if (val <= min) {
                return 0.0;
            }
            if (val > max) {
                return 1.0;
            }
            if (val == max) {
                return 1.0 - 1.0 / ndv;
            }
            return (val - min) / (max - min);
        }
        if (cp instanceof LessThanEqual) {
            if (val < min) {
                return 0.0;
            }
            if (val == min) {
                return 1.0 / ndv;
            }
            if (val >= max) {
                return 1.0;
            }
            return (val - min) / (max - min);
        }
        if (cp instanceof GreaterThan) {
            if (val >= max) {
                return 0.0;
            }
            if (val == min) {
                return 1.0 - 1.0 / ndv;
            }
            if (val < min) {
                return 1.0;
            }
            return (max - val) / (max - min);
        }
        if (cp instanceof GreaterThanEqual) {
            if (val > max) {
                return 0.0;
            }
            if (val == max) {
                return 1.0 / ndv;
            }
            if (val <= min) {
                return 1.0;
            }
            return (max - val) / (max - min);
        }
        throw new RuntimeException(String.format("Unexpected expression : %s", cp.toSql()));
    }

    private double calculateWhenBothChildIsColumn(ComparisonPredicate cp,
            ColumnStatistic statsForLeft, ColumnStatistic statsForRight) {
        double leftMin = statsForLeft.minValue;
        double rightMin = statsForRight.minValue;
        double leftMax = statsForLeft.maxValue;
        double rightMax = statsForRight.maxValue;
        if (cp instanceof EqualTo) {
            if (!statsForLeft.hasIntersect(statsForRight)) {
                return 0.0;
            }
            return DEFAULT_EQUALITY_COMPARISON_SELECTIVITY;
        }
        if (cp instanceof GreaterThan) {
            if (leftMax <= rightMin) {
                return 0.0;
            } else if (leftMin >= rightMax) {
                return 1.0;
            } else {
                return DEFAULT_INEQUALITY_COMPARISON_SELECTIVITY;
            }
        }
        if (cp instanceof GreaterThanEqual) {
            if (leftMax < rightMin) {
                return 0.0;
            } else if (leftMin > rightMax) {
                return 1.0;
            } else {
                return DEFAULT_INEQUALITY_COMPARISON_SELECTIVITY;
            }
        }
        if (cp instanceof LessThan) {
            if (leftMin >= rightMax) {
                return 0.0;
            } else if (leftMax <= rightMin) {
                return 1.0;
            } else {
                return DEFAULT_INEQUALITY_COMPARISON_SELECTIVITY;
            }
        }
        if (cp instanceof LessThanEqual) {
            if (leftMin > rightMax) {
                return 0.0;
            } else if (leftMax < rightMin) {
                return 1.0;
            } else {
                return DEFAULT_INEQUALITY_COMPARISON_SELECTIVITY;
            }
        }
        throw new RuntimeException(String.format("Unexpected expression : %s", cp.toSql()));
    }

    @Override
    public StatsDeriveResult visitInPredicate(InPredicate inPredicate, EstimationContext context) {
        boolean isNotIn = context != null && context.isNot;
        Expression compareExpr = inPredicate.getCompareExpr();
        ColumnStatistic compareExprStats = ExpressionEstimation.estimate(compareExpr, inputStats);
        if (compareExprStats == ColumnStatistic.UNKNOWN) {
            return inputStats;
        }
        List<Expression> options = inPredicate.getOptions();
        double maxOption = 0;
        double minOption = Double.MAX_VALUE;
        /* suppose A.(min, max) = (0, 10), A.ndv=10
         A in ( 1, 2, 5, 100):
              validInOptCount = 3, that is (1, 2, 5)
              table selectivity = 3/10
              A.min = 1, A.max=5
              A.selectivity = 3/5
              A.ndv = 3
         A not in (1, 2, 3, 100):
              validInOptCount = 10 - 3
              we assume that 1, 2, 3 exist in A
              A.ndv = 10 - 3 = 7
              table selectivity = 7/10
              A.(min, max) not changed
              A.selectivity = 7/10
        */
        double validInOptCount = 0;
        double columnSelectivity = 1.0;
        double selectivity = 1.0;
        ColumnStatisticBuilder compareExprStatsBuilder = new ColumnStatisticBuilder(compareExprStats);
        if (isNotIn) {
            for (Expression option : options) {
                ColumnStatistic optionStats = ExpressionEstimation.estimate(option, inputStats);
                if (optionStats == ColumnStatistic.UNKNOWN) {
                    continue;
                }
                double validOptionNdv = compareExprStats.ndvIntersection(optionStats);
                if (validOptionNdv > 0.0) {
                    validInOptCount += validOptionNdv;
                }
            }
            validInOptCount = Math.max(1, compareExprStats.ndv - validInOptCount);
            columnSelectivity = Math.max(1, validInOptCount)
                    / compareExprStats.ndv;
        } else {
            for (Expression option : options) {
                ColumnStatistic optionStats = ExpressionEstimation.estimate(option, inputStats);
                if (optionStats == ColumnStatistic.UNKNOWN) {
                    validInOptCount++;
                    continue;
                }
                double validOptionNdv = compareExprStats.ndvIntersection(optionStats);
                if (validOptionNdv > 0.0) {
                    validInOptCount += validOptionNdv;
                    maxOption = Math.max(optionStats.maxValue, maxOption);
                    minOption = Math.min(optionStats.minValue, minOption);
                }
            }
            maxOption = Math.min(maxOption, compareExprStats.maxValue);
            minOption = Math.max(minOption, compareExprStats.minValue);
            if (maxOption == minOption) {
                columnSelectivity = 1.0;
            } else {
                double outputRange = maxOption - minOption;
                double originRange = Math.max(1, compareExprStats.maxValue - compareExprStats.minValue);
                double orginDensity = compareExprStats.ndv / originRange;
                double outputDensity = validInOptCount / outputRange;
                columnSelectivity = Math.min(1, outputDensity / orginDensity);
            }
            compareExprStatsBuilder.setMaxValue(maxOption);
            compareExprStatsBuilder.setMinValue(minOption);
        }

        selectivity = Math.min(1.0, validInOptCount / compareExprStats.ndv);

        compareExprStatsBuilder.setSelectivity(compareExprStats.selectivity * columnSelectivity);
        compareExprStatsBuilder.setNdv(validInOptCount);

        StatsDeriveResult estimated = new StatsDeriveResult(inputStats);

        estimated = estimated.updateRowCountOnCopy(selectivity);
        if (compareExpr instanceof SlotReference) {
            estimated.addColumnStats(((SlotReference) compareExpr).getExprId(),
                    compareExprStatsBuilder.build());
        }
        return estimated;
    }

    @Override
    public StatsDeriveResult visitNot(Not not, EstimationContext none) {
        Preconditions.checkState(!(not.child() instanceof Not),
                "Consecutive Not statement should be merged previously");
        EstimationContext context = new EstimationContext();
        context.isNot = true;
        return not.child().accept(this, context);
    }

    static class EstimationContext {
        private boolean isNot;
    }

}
