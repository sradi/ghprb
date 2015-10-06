package org.jenkinsci.plugins.ghprb;

import hudson.model.BuildBadgeAction;

import java.net.URL;

public class GhprbBadgeAction implements BuildBadgeAction {
	
	private int pullRequestId;
	private URL pullRequestUrl;
	private String pullRequestTitle;
	
	public GhprbBadgeAction(int pullRequestId, URL pullRequestUrl, String pullRequestTitle) {
		this.pullRequestId = pullRequestId;
		this.pullRequestUrl = pullRequestUrl;
		this.pullRequestTitle = pullRequestTitle;
	}

	public String getIconFileName() {
		return null;
	}

	public String getDisplayName() {
		return null;
	}

	public String getUrlName() {
		return null;
	}
	
	public URL getUrl() {
		return pullRequestUrl;
	}
	
	public String getText() {
		return String.valueOf(pullRequestId + ": " + pullRequestTitle);
	}
	
	

}
