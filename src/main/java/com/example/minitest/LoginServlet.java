package com.example.minitest;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.dbcp2.BasicDataSource;

import org.owasp.validator.html.*;

public class LoginServlet extends GenericServlet {
	private static final long serialVersionUID = 1L;
	private AntiSamy as;
	private Policy policy;
	
	@Override
	public void init() {
		try {
		    InputStream policyFile = getServletContext().getResourceAsStream("/WEB-INF/antisamy-policy.xml" );
		    policy = Policy.getInstance(policyFile);
		    as = new AntiSamy(policy);
		} catch (PolicyException e) {
		    System.out.println("ERROR: Policy file not loaded.");  
		}
	}
	
	@Override
	public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
//		String userId = Utility.cleanInputAsString(req.getParameter("userId"));
//		String password = Utility.cleanInputAsString(req.getParameter("password"));
		
		String userId = null;
		try {
			CleanResults uidCr = as.scan(req.getParameter("userId"),policy);
			userId = uidCr.getCleanHTML();
		} catch (ScanException e) {
			e.printStackTrace();
		} catch (PolicyException e) {
			e.printStackTrace();
		}
		String password = null;
		try {
			CleanResults pwdCr = as.scan(req.getParameter("password"),policy);
			password = pwdCr.getCleanHTML();
		} catch (ScanException e) {
			e.printStackTrace();
		} catch (PolicyException e) {
			e.printStackTrace();
		}
		
		res.setContentType("text/html");
		PrintWriter out = res.getWriter();
		out.println("<html><head><title>Hello World!</title></head>");
		if (userId != null && !"".equals(userId)) {
			String userBlock = null;
			try {
				CleanResults userCr = as.scan(getUser(userId),policy);
				userBlock = userCr.getCleanHTML();
			} catch (ScanException e) {
				e.printStackTrace();
			} catch (PolicyException e) {
				e.printStackTrace();
			}
			out.println("<body><h1>Hello User " + userId + "</h1>" + userBlock + "</body></html>");
		} else {
			out.println("<body><h1>Hello World!</h1></body></html>");
		}
	}
	
	private static String getUser(String userId) {
		Connection conn = null;
		Statement stmt = null;
		ResultSet rs = null;
		StringBuffer result = new StringBuffer();
		try {
			BasicDataSource bds = DataSource.getInstance().getBds();
			conn = bds.getConnection();
			stmt = conn.createStatement();
			String query = " select * from users where id = " + userId;
	        rs = stmt.executeQuery(query);
	        while (rs.next()) {
	        	result.append("<li>" + rs.getInt(1)+ " " + rs.getString(2) + " " + rs.getString(3)+ " " + rs.getString(4)+ " " + rs.getString(5) + "</li>");
	        }
	        if ("".equals(result.toString())) {
	        	result.append("Userid=" + userId + " not found");
	        }
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		} finally {
			try {
				if (rs != null) 
					rs.close();
				if (stmt != null)
					stmt.close();
				if (conn != null) 
					conn.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		return result.toString();
	}

}
