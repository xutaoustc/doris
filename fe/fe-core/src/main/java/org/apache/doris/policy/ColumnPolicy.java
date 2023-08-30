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

package org.apache.doris.policy;

import org.apache.doris.catalog.Column;
import org.apache.doris.catalog.Database;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.ScalarType;
import org.apache.doris.catalog.Table;
import org.apache.doris.common.AnalysisException;
import org.apache.doris.common.io.Text;
import org.apache.doris.common.io.Writable;
import org.apache.doris.persist.gson.GsonUtils;
import org.apache.doris.qe.ShowResultSetMetaData;

import com.google.common.collect.Lists;
import com.google.gson.annotations.SerializedName;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.List;

/**
 * Save policy for filtering data.
 **/
@Data
public class ColumnPolicy implements Writable {

    public static final ShowResultSetMetaData ROW_META_DATA =
            ShowResultSetMetaData.builder()
                .addColumn(new Column("PolicyName", ScalarType.createVarchar(100)))
                .addColumn(new Column("DbName", ScalarType.createVarchar(100)))
                .addColumn(new Column("TableName", ScalarType.createVarchar(100)))
                .addColumn(new Column("Role", ScalarType.createVarchar(100)))
                .addColumn(new Column("columns", ScalarType.createVarchar(65535)))
                .addColumn(new Column("OriginStmt", ScalarType.createVarchar(65535)))
                .build();

    private static final Logger LOG = LogManager.getLogger(ColumnPolicy.class);

    @SerializedName(value = "policyId")
    protected long policyId = -1;

    @SerializedName(value = "policyName")
    protected String policyName = null;

    /**
     * Policy bind role.
     **/
    @SerializedName(value = "role")
    private String role = null;

    @SerializedName(value = "dbId")
    private long dbId = -1;

    @SerializedName(value = "tableId")
    private long tableId = -1;

    /**
     * Use for Serialization/deserialization.
     **/
    @SerializedName(value = "originStmt")
    private String originStmt;

    @SerializedName(value = "columns")
    private String columns = null;

    /**
     * Policy for Table. Policy of ROW or others.
     *
     * @param policyId policy id
     * @param policyName policy name
     * @param dbId database i
     * @param originStmt origin stmt
     * @param tableId table id
     * @param columns where predicate
     */
    public ColumnPolicy(long policyId, final String policyName, long dbId, String role, String originStmt,
                        final long tableId, final String columns) {

        this.policyId = policyId;
        this.policyName = policyName;
        this.dbId = dbId;
        this.tableId = tableId;
        this.role = role;
        this.originStmt = originStmt;
        this.columns = columns;
    }

    public ColumnPolicy() {

    }

    /**
     * Use for SHOW POLICY.
     **/
    public List<String> getShowInfo() throws AnalysisException {
        Database database = Env.getCurrentInternalCatalog().getDbOrAnalysisException(this.dbId);
        Table table = database.getTableOrAnalysisException(this.tableId);
        return Lists.newArrayList(this.policyName, database.getFullName(), table.getName(), this.role,
            this.columns, this.originStmt);
    }

    @Override
    public ColumnPolicy clone() {
        return new ColumnPolicy(this.policyId, this.policyName, this.dbId, this.role, this.originStmt,
            this.tableId, this.columns);
    }

    @Override
    public void write(DataOutput out) throws IOException {
        Text.writeString(out, GsonUtils.GSON.toJson(this));
    }

    /**
     * Read Policy from file.
     **/
    public static ColumnPolicy read(DataInput in) throws IOException {
        String json = Text.readString(in);
        return GsonUtils.GSON.fromJson(json, ColumnPolicy.class);
    }

    private boolean checkMatched(long dbId, long tableId,
                                 String policyName, String role) {
        return (policyName == null || StringUtils.equals(policyName, this.policyName))
                && (dbId == -1 || dbId == this.dbId)
                && (tableId == -1 || tableId == this.tableId)
                && (this.role == null ? false : StringUtils.equals(role, this.role));
    }

    public boolean matchPolicy(ColumnPolicy checkedPolicyCondition) {
        if (!(checkedPolicyCondition instanceof ColumnPolicy)) {
            return false;
        }
        ColumnPolicy columnPolicy = (ColumnPolicy) checkedPolicyCondition;
        return checkMatched(columnPolicy.getDbId(), columnPolicy.getTableId(),
                            columnPolicy.getPolicyName(), columnPolicy.getRole());
    }

    public boolean matchPolicy(DropColumnPolicyLog checkedDropPolicyLogCondition) {
        return checkMatched(checkedDropPolicyLogCondition.getDbId(), checkedDropPolicyLogCondition.getTableId(),
                            checkedDropPolicyLogCondition.getPolicyName(), checkedDropPolicyLogCondition.getRole());
    }
}
