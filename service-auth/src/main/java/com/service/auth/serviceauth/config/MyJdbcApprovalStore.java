package com.service.auth.serviceauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;

import javax.sql.DataSource;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

/**
 * 自定义默认授权时间
 */
@Slf4j
public class MyJdbcApprovalStore extends JdbcApprovalStore {

    public MyJdbcApprovalStore(DataSource dataSource) {
        super(dataSource);
    }

    @Override
    public boolean addApprovals(Collection<Approval> approvals) {
        Iterator var3 = approvals.iterator();
        long curren = System.currentTimeMillis();
        curren += 30 * 60 * 1000;
        Date da = new Date(curren);
        while(var3.hasNext()) {
            Approval approval = (Approval)var3.next();
            approval.setExpiresAt(da);
        }
        return super.addApprovals(approvals);
    }
}
