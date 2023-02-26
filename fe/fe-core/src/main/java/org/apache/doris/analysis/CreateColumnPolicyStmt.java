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

package org.apache.doris.analysis;


import org.apache.doris.catalog.Env;
import org.apache.doris.cluster.ClusterNamespace;
import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.ErrorReport;
import org.apache.doris.common.FeNameFormat;
import org.apache.doris.common.UserException;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.qe.ConnectContext;

import lombok.Getter;

public class CreateColumnPolicyStmt extends DdlStmt {

    @Getter
    private final boolean ifNotExists;

    @Getter
    private final String policyName;

    @Getter
    private TableName tableName = null;

    @Getter
    private String role = null;

    @Getter
    private String columns;

    /**
     * Use for cup.
     **/
    public CreateColumnPolicyStmt(boolean ifNotExists, String policyName, TableName tableName,
                                  String role, String columns) {
        this.ifNotExists = ifNotExists;
        this.policyName = policyName;
        this.tableName = tableName;
        this.role = role;
        this.columns = columns;
    }

    @Override
    public void analyze(Analyzer analyzer) throws UserException {
        super.analyze(analyzer);
        tableName.analyze(analyzer);
        FeNameFormat.checkRoleName(role, false /* can not be admin */, "Can not create row policy to role");
        role = ClusterNamespace.getFullName(analyzer.getClusterName(), role);

        // check auth
        if (!Env.getCurrentEnv().getAccessManager().checkGlobalPriv(ConnectContext.get(), PrivPredicate.ADMIN)) {
            ErrorReport.reportAnalysisException(ErrorCode.ERR_SPECIFIC_ACCESS_DENIED_ERROR, "ADMIN");
        }
    }

    @Override
    public String toSql() {
        StringBuilder sb = new StringBuilder();
        sb.append("CREATE ").append("COLUMN").append(" POLICY ");
        if (ifNotExists) {
            sb.append("IF NOT EXISTS");
        }
        sb.append(policyName);
        sb.append(" ON ").append(tableName.toSql())
            .append(" TO ").append(role).append(" USING ").append(columns);
        return sb.toString();
    }
}
