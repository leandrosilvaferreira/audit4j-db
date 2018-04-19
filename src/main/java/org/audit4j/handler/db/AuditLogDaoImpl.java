/*
 * Copyright (c) 2014-2015 Janith Bandara, This source is a part of
 * Audit4j - An open source auditing framework.
 * http://audit4j.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.audit4j.handler.db;

import static org.audit4j.handler.db.Utils.checkNotEmpty;

import java.lang.reflect.Type;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.audit4j.core.dto.AuditEvent;
import org.audit4j.core.dto.Field;
import org.audit4j.core.exception.HandlerException;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import lombok.NonNull;

/**
 * This class is used to create audit tables and submit audit events to JDBC supported data stores.
 *
 * @author <a href="mailto:janith3000@gmail.com">Janith Bandara</a>
 * @author Thebora Kompanioni https://github.com/theborakompanioni
 * @author Kettner, MA (ITOPT2) - KLM <Mark.Kettner@klm.com> - For Oracle Support
 */
final class AuditLogDaoImpl extends AuditBaseDao implements AuditLogDao {

	/** The table name. */
	private final String tableName;

	/** The schema name. */
	private final String schemaName;

	/** The insert query. */
	private final String insertQuery;

	/**
	 * Instantiates a new audit log dao.
	 *
	 * @param tableName
	 *            given through the constructor to create table.
	 * @throws HandlerException
	 *             the handler exception
	 */
	AuditLogDaoImpl(final String tableName, final String schema) throws HandlerException {
		this.tableName = checkNotEmpty(tableName, "Table name must not be empty");
		this.schemaName = schema;
		final StringBuilder insertQueryBuilder = new StringBuilder();
		insertQueryBuilder.append("insert into ");
		if (!StringUtils.isEmpty(schema)) {
			insertQueryBuilder.append(schema).append(".");
		}
		insertQueryBuilder.append(tableName).append("(identifier, timestamp, actor, origin, action, elements) values (?, ?, ?, ?, ?, ?)");
		this.insertQuery = insertQueryBuilder.toString();

		this.createTableIfNotExists();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see org.audit4j.handler.db.AuditLogDao#writeEvent(org.audit4j.core.dto.AuditEvent)
	 */
	@Override
	public boolean writeEvent(final AuditEvent event) throws HandlerException {

		final StringBuilder elements = new StringBuilder();

		// Adapted to saves in JSON format

		// for (Field element : event.getFields()) {
		// elements.append(element.getName() + " " + element.getType() + ":" + element.getValue() + ", ");
		// }

		elements.append(new Gson().toJson(event.getFields()));

		try (Connection conn = this.getConnection()) {
			try (PreparedStatement statement = conn.prepareStatement(this.insertQuery)) {
				statement.setString(1, event.getUuid().toString());
				statement.setTimestamp(2, new Timestamp(event.getTimestamp().getTime()));
				statement.setString(3, event.getActor());
				statement.setString(4, event.getOrigin());
				statement.setString(5, event.getAction());
				statement.setString(6, elements.toString());

				return statement.execute();
			}
		}
		catch (final SQLException e) {
			throw new HandlerException("SQL Exception", DatabaseAuditHandler.class, e);
		}
	}

	/**
	 * Creates the table in the database based on the table name given through constructor. This supports to different
	 * databases including Oracle, MySQL, Postgress and HSQLDB.
	 *
	 * @return true, if successful
	 * @throws HandlerException
	 *             the handler exception
	 */
	private boolean createTableIfNotExists() throws HandlerException {

		boolean result = false;
		try (Connection conn = this.getConnection()) {
			final StringBuilder query = new StringBuilder();
			final String tableNameWithSchema = (!StringUtils.isEmpty(this.schemaName)) ? (this.schemaName + "." + this.tableName) : this.tableName;

			if (this.isOracleDatabase()) {
				// Create table if Oracle Database
				// String values[] = tableName.split("\\.");
				query.append("select count(*) from all_tables where table_name = upper('").append(this.tableName).append("')");
				try (PreparedStatement statement = conn.prepareStatement(query.toString())) {
					result = statement.execute();
				}
				if (result == false) {
					query.append("create table ").append(tableNameWithSchema).append(" (").append("identifier VARCHAR2(200) NOT NULL,").append("timestamp TIMESTAMP NOT NULL,")
							.append("actor VARCHAR2(200) NOT NULL,").append("origin VARCHAR2(200),").append("action VARCHAR2(200) NOT NULL,").append("elements CLOB").append(");");
				}
			}
			else if (this.isHSQLDatabase()) {
				// Create Table if HSQLDB database
				query.append("create table if not exists ").append(tableNameWithSchema).append(" (").append("identifier VARCHAR(200) NOT NULL,").append("timestamp TIMESTAMP NOT NULL,")
						.append("actor VARCHAR(200) NOT NULL,").append("origin VARCHAR(200),").append("action VARCHAR(200) NOT NULL,").append("elements LONGVARCHAR").append(");");
				try (PreparedStatement statement = conn.prepareStatement(query.toString())) {
					result = statement.execute();
				}
			}
			else if (this.isMySQLDatabase()) {
				// Create table if MySQL database

				//@formatter:off
				query
					.append("create table if not exists ")
					.append(tableNameWithSchema)
					.append(" (")
					.append("identifier VARCHAR(200) NOT NULL,")
					.append("timestamp TIMESTAMP NOT NULL,")
					.append("actor VARCHAR(200) NOT NULL,")
					.append("origin VARCHAR(200),")
					.append("action VARCHAR(200) NOT NULL,")
					.append("elements TEXT")
					.append(");");

				try (PreparedStatement statement = conn.prepareStatement(query.toString())) {
					result = statement.execute();
				}

				this.createMysqlIndex("actor", "ASC");
				this.createMysqlIndex("timestamp", "DESC");

				//@formatter:on
			}
			else if (this.isSQLServerDatabase()) {
				// Create table if SQLServer database
				query.append(" IF OBJECT_ID(N'" + tableNameWithSchema + "', N'U') IS NULL BEGIN ");
				query.append("create table ").append(tableNameWithSchema).append(" (").append("identifier VARCHAR(200) NOT NULL,").append("timestamp DATETIME NOT NULL,")
						.append("actor VARCHAR(200) NOT NULL,").append("origin VARCHAR(200),").append("action VARCHAR(200) NOT NULL,").append("elements TEXT").append(");");
				query.append(" END ");
				try (PreparedStatement statement = conn.prepareStatement(query.toString())) {
					result = statement.execute();
				}
			}
			else {
				query.append("create table if not exists ").append(tableNameWithSchema).append(" (").append("identifier VARCHAR(200) NOT NULL,").append("timestamp TIMESTAMP NOT NULL,")
						.append("actor VARCHAR(200) NOT NULL,").append("origin VARCHAR(200),").append("action VARCHAR(200) NOT NULL,").append("elements VARCHAR(70000)").append(");");
				try (PreparedStatement statement = conn.prepareStatement(query.toString())) {
					result = statement.execute();
				}
			}
			return result;
		}
		catch (final SQLException e) {
			throw new HandlerException("SQL Exception", DatabaseAuditHandler.class, e);
		}
	}

	private boolean createMysqlIndex(@NonNull final String columnName, final String order) throws HandlerException {

		try (Connection conn = this.getConnection()) {

			final String schema = this.schemaName != null ? this.schemaName : conn.getSchema();
			final String schemaAndTableName = (schema != null ? schema + "." : "") + this.tableName;
			final String indexName = (schema != null ? schema + "_" : "") + this.tableName + "_" + columnName + "_IDX";

			if (!this.existsMysqlIndex(indexName)) {

				final StringBuilder createIndexQuery = new StringBuilder();
				createIndexQuery.append("ALTER TABLE " + schemaAndTableName + " ADD INDEX `" + indexName + "` (`" + columnName + "` " + (order != null ? order : "ASC") + ")");

				try (PreparedStatement statement = conn.prepareStatement(createIndexQuery.toString())) {
					return statement.execute();
				}
			}
		}
		catch (final SQLException e) {
			throw new HandlerException("SQL Exception", DatabaseAuditHandler.class, e);
		}

		return false;
	}

	private boolean existsMysqlIndex(final String indexName) throws HandlerException {

		try (Connection conn = this.getConnection()) {

			final String schema = this.schemaName != null ? this.schemaName : conn.getSchema();

			final StringBuilder query = new StringBuilder();
			query.append(" SELECT count(*) AS count FROM INFORMATION_SCHEMA.STATISTICS WHERE ");
			query.append(" TABLE_NAME = ? AND INDEX_NAME = ? ");

			if (schema != null) {
				query.append(" AND TABLE_SCHEMA = ? ");
			}

			ResultSet rs = null;

			try (PreparedStatement statement = conn.prepareStatement(query.toString())) {

				statement.setString(1, this.tableName);
				statement.setString(2, indexName);

				if (schema != null) {
					statement.setString(3, schema);
				}

				rs = statement.executeQuery();

				while (rs.next()) {
					return rs.getInt("count") > 0;
				}
			}
			finally {
				if (rs != null) {
					rs.close();
				}
			}

		}
		catch (final SQLException e) {
			throw new HandlerException("SQL Exception", DatabaseAuditHandler.class, e);
		}

		return false;
	}

	@Override
	public List<AuditEvent> findAuditEventsByActor(@NonNull final String actor, final Integer limit) throws HandlerException {

		final List<AuditEvent> result = new ArrayList<>();

		try (Connection conn = this.getConnection()) {
			final StringBuilder query = new StringBuilder();
			final String tableNameWithSchema = (!StringUtils.isEmpty(this.schemaName)) ? (this.schemaName + "." + this.tableName) : this.tableName;

			if (this.isOracleDatabase()) {
				throw new UnsupportedOperationException("findAuditEventsByActor not implemented to Oracle");
			}
			else if (this.isHSQLDatabase()) {
				throw new UnsupportedOperationException("findAuditEventsByActor not implemented to HSQLDB");
			}
			else if (this.isMySQLDatabase()) {
				// Select auditevents from table if MySQL database

				//@formatter:off
				query
				.append(" SELECT identifier, `timestamp`, actor, origin, `action`, elements FROM  ")
				.append(tableNameWithSchema)
				.append(" WHERE actor = ? ")
				.append(" ORDER BY `timestamp` DESC ");

				if(limit != null){
					query.append(" LIMIT ?");
				}
				//@formatter:on

				ResultSet rs = null;

				try (PreparedStatement statement = conn.prepareStatement(query.toString())) {

					statement.setString(1, actor);

					if (limit != null) {
						statement.setInt(2, limit);
					}

					rs = statement.executeQuery();

					while (rs.next()) {

						final Type listType = new TypeToken<ArrayList<Field>>() {
						}.getType();
						final List<Field> fields = new Gson().fromJson(rs.getString("elements"), listType);

						final AuditEvent auditEvent = new AuditEvent(rs.getString("actor"), rs.getString("action"), rs.getString("origin"), fields.toArray(new Field[fields.size()]));
						auditEvent.setUuid(Long.valueOf(rs.getString("identifier")));
						auditEvent.setTimestamp(rs.getTimestamp("timestamp"));

						result.add(auditEvent);
					}
				}
				finally {
					if (rs != null) {
						rs.close();
					}
				}
			}
			else if (this.isSQLServerDatabase()) {
				throw new UnsupportedOperationException("findAuditEventsByActor not implemented to SQL Server");
			}
			else {
				throw new UnsupportedOperationException("findAuditEventsByActor not implemented to ?????");
			}
			return result;
		}
		catch (final SQLException e) {
			throw new HandlerException("SQL Exception", DatabaseAuditHandler.class, e);
		}
	}
}
