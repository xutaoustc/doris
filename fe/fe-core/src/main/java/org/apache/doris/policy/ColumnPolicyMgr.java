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

import org.apache.doris.analysis.CreateColumnPolicyStmt;
import org.apache.doris.analysis.DropColumnPolicyStmt;
import org.apache.doris.analysis.ShowColumnPolicyStmt;
import org.apache.doris.catalog.DatabaseIf;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.TableIf;
import org.apache.doris.cluster.ClusterNamespace;
import org.apache.doris.common.AnalysisException;
import org.apache.doris.common.DdlException;
import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.ErrorReport;
import org.apache.doris.common.UserException;
import org.apache.doris.common.io.Text;
import org.apache.doris.common.io.Writable;
import org.apache.doris.persist.gson.GsonUtils;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.ShowResultSet;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * Management policy and cache it.
 **/
public class ColumnPolicyMgr implements Writable {
    private static final Logger LOG = LogManager.getLogger(ColumnPolicyMgr.class);

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    @SerializedName(value = "policies")
    private List<ColumnPolicy> policies = new ArrayList<>();

    /**
     * Cache merge policy for match.
     * key：dbId:tableId-type-user
     **/
    private Map<Long, Map<String, RowPolicy>> dbIdToMergeTablePolicyMap = Maps.newConcurrentMap();

    private Set<String> rolePolicySet = Sets.newConcurrentHashSet();

    private void writeLock() {
        lock.writeLock().lock();
    }

    private void writeUnlock() {
        lock.writeLock().unlock();
    }

    private void readLock() {
        lock.readLock().lock();
    }

    private void readUnlock() {
        lock.readLock().unlock();
    }

    /**
     * Create policy through stmt.
     **/
    public void createPolicy(CreateColumnPolicyStmt stmt) throws UserException {
        long policyId = Env.getCurrentEnv().getNextId();
        DatabaseIf db = Env.getCurrentEnv().getCatalogMgr()
                .getCatalogOrAnalysisException(stmt.getTableName().getCtl())
                .getDbOrAnalysisException(stmt.getTableName().getDb());
        TableIf table = db.getTableOrAnalysisException(stmt.getTableName().getTbl());
        ColumnPolicy policy = new ColumnPolicy(policyId, stmt.getPolicyName(), db.getId(), stmt.getRole(),
                stmt.getOrigStmt().originStmt, table.getId(), stmt.getColumns());

        writeLock();
        try {
            if (existPolicy(policy)) {
                if (stmt.isIfNotExists()) {
                    return;
                }
                throw new DdlException("the policy " + policy.getPolicyName() + " already create");
            }
            unprotectedAdd(policy);
            Env.getCurrentEnv().getEditLog().logCreateColumnPolicy(policy);
        } finally {
            writeUnlock();
        }
    }

    /**
     * Drop policy through stmt.
     **/
    public void dropPolicy(DropColumnPolicyStmt stmt) throws DdlException, AnalysisException {
        DropColumnPolicyLog dropPolicyLog = DropColumnPolicyLog.fromDropStmt(stmt);
        writeLock();
        try {
            if (!existPolicy(dropPolicyLog)) {
                if (stmt.isIfExists()) {
                    return;
                }
                throw new DdlException("the policy " + dropPolicyLog.getPolicyName() + " not exist");
            }
            unprotectedDrop(dropPolicyLog);
            Env.getCurrentEnv().getEditLog().logDropColumnPolicy(dropPolicyLog);
        } finally {
            writeUnlock();
        }
    }

    /**
     * Check whether this user has policy.
     *
     * @param role role who has policy
     * @return exist or not
     */
    public void checkPolicy(String dbName, String tableName, String role,
                            Collection<String> columns) throws AnalysisException {
        DatabaseIf db = Env.getCurrentEnv().getCatalogMgr()
                .getCatalogOrAnalysisException("internal")
                .getDbOrAnalysisException(dbName);
        TableIf table = db.getTableOrAnalysisException(tableName);

        final String roleCluster = ClusterNamespace.getFullName("default_cluster", role);

        List<ColumnPolicy> policies = this.policies.stream().filter(p ->
                p.getRole().equals(roleCluster) && p.getDbId() == db.getId() && p.getTableId() == table.getId()
        ).collect(Collectors.toList());

        if (policies == null || policies.size() == 0) {
            return;
        }

        ColumnPolicy policy = policies.get(0);
        Set<String> expectedColumns = new HashSet<>(Arrays.asList(policy.getColumns().split(",")));
        expectedColumns.add("__DORIS_DELETE_SIGN__");
        expectedColumns.add("__DORIS_SEQUENCE_COL__");

        for (String column : columns) {
            if (! expectedColumns.contains(column)) {
                ErrorReport.reportAnalysisException(ErrorCode.ERR_COLUMNACCESS_DENIED_ERROR, "SELECT",
                        ConnectContext.get().getQualifiedUser(), ConnectContext.get().getRemoteIP(),
                        column,
                        dbName + ": " + tableName);
            }
        }
    }

    /**
     * Check whether the policy exist.
     *
     * @param checkedPolicy policy condition to check
     * @return exist or not
     */
    public boolean existPolicy(ColumnPolicy checkedPolicy) {
        readLock();
        try {
            return policies.stream().anyMatch(policy -> policy.matchPolicy(checkedPolicy));
        } finally {
            readUnlock();
        }
    }

    private boolean existPolicy(DropColumnPolicyLog checkedDropPolicy) {
        readLock();
        try {
            return policies.stream().anyMatch(policy -> policy.matchPolicy(checkedDropPolicy));
        } finally {
            readUnlock();
        }
    }

    public void replayCreate(ColumnPolicy policy) {
        unprotectedAdd(policy);
        LOG.info("replay create policy: {}", policy);
    }

    private void unprotectedAdd(ColumnPolicy policy) {
        if (policy == null) {
            return;
        }
        policies.add(policy);
    }

    public void replayDrop(DropColumnPolicyLog log) {
        unprotectedDrop(log);
        LOG.info("replay drop policy log: {}", log);
    }

    private void unprotectedDrop(DropColumnPolicyLog log) {
        policies.removeIf(policy -> {
            if (policy.matchPolicy(log)) {
                return true;
            }
            return false;
        });
    }

    public ShowResultSet showPolicy(ShowColumnPolicyStmt showStmt) throws AnalysisException {
        List<List<String>> rows = Lists.newArrayList();
        long currentDbId = ConnectContext.get().getCurrentDbId();
        ColumnPolicy checkedPolicy = null;

        ColumnPolicy columnPolicy = new ColumnPolicy();
        if (currentDbId != -1) {
            columnPolicy.setDbId(currentDbId);
        }
        if (StringUtils.isNotBlank(showStmt.getRole())) {
            columnPolicy.setRole(showStmt.getRole());
        }
        checkedPolicy = columnPolicy;

        final ColumnPolicy finalCheckedPolicy = checkedPolicy;
        readLock();
        try {
            List<ColumnPolicy> finalPolicies = policies.stream()
                    .filter(p -> p.matchPolicy(finalCheckedPolicy)).collect(Collectors.toList());
            for (ColumnPolicy policy : finalPolicies) {
                rows.add(policy.getShowInfo());
            }
            return new ShowResultSet(showStmt.getMetaData(), rows);
        } finally {
            readUnlock();
        }
    }

    @Override
    public void write(DataOutput out) throws IOException {
        Text.writeString(out, GsonUtils.GSON.toJson(this));
    }

    /**
     * Read policyMgr from file.
     **/
    public static ColumnPolicyMgr read(DataInput in) throws IOException {
        String json = Text.readString(in);
        ColumnPolicyMgr policyMgr = GsonUtils.GSON.fromJson(json, ColumnPolicyMgr.class);
        return policyMgr;
    }
}
