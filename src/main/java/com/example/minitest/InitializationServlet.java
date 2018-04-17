package com.example.minitest;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.dbcp2.BasicDataSource;

public class InitializationServlet extends GenericServlet {

	private static final long serialVersionUID = 1L;

	@Override
	public void service(ServletRequest arg0, ServletResponse arg1) throws ServletException, IOException {
		// null
	}
	public void init() throws ServletException {
		// Create the in-memory db schema and load data
		// As simple as possible, but far from attractive
		Connection conn = null;
		Statement stmt = null;
		ResultSet rs = null;
		try {
			BasicDataSource bds = DataSource.getInstance().getBds();
			conn = bds.getConnection();
			stmt = conn.createStatement();
			stmt.execute("create table users (id number, name varchar(50), email varchar(100),password varchar(50), admin_role char(1))");
	        stmt.execute("insert into users values (1,'admin','admin@example.com','admin123','1')");
	        stmt.execute("insert into users values (2,'standard','standard@example.com','user123','2')");
	        stmt.execute("insert into users values (3,'guest','guest@example.com','guest','3')");
	        rs = stmt.executeQuery("select * from users");
	        while (rs.next()) {
	        	System.out.println(rs.getInt(1)+ " " + rs.getString(2) + " " + rs.getString(3)+ " " + rs.getString(4)+ " " + rs.getString(5));
	        }
		} catch (SQLException e) {
			e.printStackTrace();
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
	}

}
