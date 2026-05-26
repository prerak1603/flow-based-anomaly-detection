package com.aegis.api.model;

import jakarta.validation.constraints.NotNull;

/**
 * Represents a single network flow record submitted for threat classification.
 * Fields mirror the NSL-KDD feature set used in Phase 2 training.
 */
public class NetworkFlow {

    @NotNull(message = "duration is required")
    private Double duration;

    @NotNull(message = "protocolType is required")
    private String protocolType;

    @NotNull(message = "service is required")
    private String service;

    @NotNull(message = "flag is required")
    private String flag;

    private Double srcBytes;
    private Double dstBytes;
    private Integer land;
    private Double wrongFragment;
    private Double urgent;
    private Double hot;
    private Double numFailedLogins;
    private Integer loggedIn;
    private Double numCompromised;
    private Integer rootShell;
    private Integer suAttempted;
    private Double numRoot;
    private Double numFileCreations;
    private Double numShells;
    private Double numAccessFiles;
    private Double numOutboundCmds;
    private Integer isHostLogin;
    private Integer isGuestLogin;
    private Double count;
    private Double srvCount;
    private Double serrorRate;
    private Double srvSerrorRate;
    private Double rerrorRate;
    private Double srvRerrorRate;
    private Double sameSrvRate;
    private Double diffSrvRate;
    private Double srvDiffHostRate;
    private Double dstHostCount;
    private Double dstHostSrvCount;
    private Double dstHostSameSrvRate;
    private Double dstHostDiffSrvRate;
    private Double dstHostSameSrcPortRate;
    private Double dstHostSrvDiffHostRate;
    private Double dstHostSerrorRate;
    private Double dstHostSrvSerrorRate;
    private Double dstHostRerrorRate;
    private Double dstHostSrvRerrorRate;

    // ── Getters & Setters ────────────────────────────────────────────────────

    public Double getDuration() { return duration; }
    public void setDuration(Double duration) { this.duration = duration; }

    public String getProtocolType() { return protocolType; }
    public void setProtocolType(String protocolType) { this.protocolType = protocolType; }

    public String getService() { return service; }
    public void setService(String service) { this.service = service; }

    public String getFlag() { return flag; }
    public void setFlag(String flag) { this.flag = flag; }

    public Double getSrcBytes() { return srcBytes; }
    public void setSrcBytes(Double srcBytes) { this.srcBytes = srcBytes; }

    public Double getDstBytes() { return dstBytes; }
    public void setDstBytes(Double dstBytes) { this.dstBytes = dstBytes; }

    public Integer getLand() { return land; }
    public void setLand(Integer land) { this.land = land; }

    public Double getWrongFragment() { return wrongFragment; }
    public void setWrongFragment(Double wrongFragment) { this.wrongFragment = wrongFragment; }

    public Double getUrgent() { return urgent; }
    public void setUrgent(Double urgent) { this.urgent = urgent; }

    public Double getHot() { return hot; }
    public void setHot(Double hot) { this.hot = hot; }

    public Double getNumFailedLogins() { return numFailedLogins; }
    public void setNumFailedLogins(Double numFailedLogins) { this.numFailedLogins = numFailedLogins; }

    public Integer getLoggedIn() { return loggedIn; }
    public void setLoggedIn(Integer loggedIn) { this.loggedIn = loggedIn; }

    public Double getNumCompromised() { return numCompromised; }
    public void setNumCompromised(Double numCompromised) { this.numCompromised = numCompromised; }

    public Integer getRootShell() { return rootShell; }
    public void setRootShell(Integer rootShell) { this.rootShell = rootShell; }

    public Integer getSuAttempted() { return suAttempted; }
    public void setSuAttempted(Integer suAttempted) { this.suAttempted = suAttempted; }

    public Double getNumRoot() { return numRoot; }
    public void setNumRoot(Double numRoot) { this.numRoot = numRoot; }

    public Double getNumFileCreations() { return numFileCreations; }
    public void setNumFileCreations(Double numFileCreations) { this.numFileCreations = numFileCreations; }

    public Double getNumShells() { return numShells; }
    public void setNumShells(Double numShells) { this.numShells = numShells; }

    public Double getNumAccessFiles() { return numAccessFiles; }
    public void setNumAccessFiles(Double numAccessFiles) { this.numAccessFiles = numAccessFiles; }

    public Double getNumOutboundCmds() { return numOutboundCmds; }
    public void setNumOutboundCmds(Double numOutboundCmds) { this.numOutboundCmds = numOutboundCmds; }

    public Integer getIsHostLogin() { return isHostLogin; }
    public void setIsHostLogin(Integer isHostLogin) { this.isHostLogin = isHostLogin; }

    public Integer getIsGuestLogin() { return isGuestLogin; }
    public void setIsGuestLogin(Integer isGuestLogin) { this.isGuestLogin = isGuestLogin; }

    public Double getCount() { return count; }
    public void setCount(Double count) { this.count = count; }

    public Double getSrvCount() { return srvCount; }
    public void setSrvCount(Double srvCount) { this.srvCount = srvCount; }

    public Double getSerrorRate() { return serrorRate; }
    public void setSerrorRate(Double serrorRate) { this.serrorRate = serrorRate; }

    public Double getSrvSerrorRate() { return srvSerrorRate; }
    public void setSrvSerrorRate(Double srvSerrorRate) { this.srvSerrorRate = srvSerrorRate; }

    public Double getRerrorRate() { return rerrorRate; }
    public void setRerrorRate(Double rerrorRate) { this.rerrorRate = rerrorRate; }

    public Double getSrvRerrorRate() { return srvRerrorRate; }
    public void setSrvRerrorRate(Double srvRerrorRate) { this.srvRerrorRate = srvRerrorRate; }

    public Double getSameSrvRate() { return sameSrvRate; }
    public void setSameSrvRate(Double sameSrvRate) { this.sameSrvRate = sameSrvRate; }

    public Double getDiffSrvRate() { return diffSrvRate; }
    public void setDiffSrvRate(Double diffSrvRate) { this.diffSrvRate = diffSrvRate; }

    public Double getSrvDiffHostRate() { return srvDiffHostRate; }
    public void setSrvDiffHostRate(Double srvDiffHostRate) { this.srvDiffHostRate = srvDiffHostRate; }

    public Double getDstHostCount() { return dstHostCount; }
    public void setDstHostCount(Double dstHostCount) { this.dstHostCount = dstHostCount; }

    public Double getDstHostSrvCount() { return dstHostSrvCount; }
    public void setDstHostSrvCount(Double dstHostSrvCount) { this.dstHostSrvCount = dstHostSrvCount; }

    public Double getDstHostSameSrvRate() { return dstHostSameSrvRate; }
    public void setDstHostSameSrvRate(Double dstHostSameSrvRate) { this.dstHostSameSrvRate = dstHostSameSrvRate; }

    public Double getDstHostDiffSrvRate() { return dstHostDiffSrvRate; }
    public void setDstHostDiffSrvRate(Double dstHostDiffSrvRate) { this.dstHostDiffSrvRate = dstHostDiffSrvRate; }

    public Double getDstHostSameSrcPortRate() { return dstHostSameSrcPortRate; }
    public void setDstHostSameSrcPortRate(Double dstHostSameSrcPortRate) { this.dstHostSameSrcPortRate = dstHostSameSrcPortRate; }

    public Double getDstHostSrvDiffHostRate() { return dstHostSrvDiffHostRate; }
    public void setDstHostSrvDiffHostRate(Double dstHostSrvDiffHostRate) { this.dstHostSrvDiffHostRate = dstHostSrvDiffHostRate; }

    public Double getDstHostSerrorRate() { return dstHostSerrorRate; }
    public void setDstHostSerrorRate(Double dstHostSerrorRate) { this.dstHostSerrorRate = dstHostSerrorRate; }

    public Double getDstHostSrvSerrorRate() { return dstHostSrvSerrorRate; }
    public void setDstHostSrvSerrorRate(Double dstHostSrvSerrorRate) { this.dstHostSrvSerrorRate = dstHostSrvSerrorRate; }

    public Double getDstHostRerrorRate() { return dstHostRerrorRate; }
    public void setDstHostRerrorRate(Double dstHostRerrorRate) { this.dstHostRerrorRate = dstHostRerrorRate; }

    public Double getDstHostSrvRerrorRate() { return dstHostSrvRerrorRate; }
    public void setDstHostSrvRerrorRate(Double dstHostSrvRerrorRate) { this.dstHostSrvRerrorRate = dstHostSrvRerrorRate; }
}
