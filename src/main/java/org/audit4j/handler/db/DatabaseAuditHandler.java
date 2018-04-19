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

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import org.audit4j.core.ErrorGuide;
import org.audit4j.core.dto.AuditEvent;
import org.audit4j.core.exception.HandlerException;
import org.audit4j.core.exception.InitializationException;
import org.audit4j.core.handler.Handler;
import org.audit4j.core.util.Log;

import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * The Class GeneralDatabaseAuditHandler.
 *
 * @author <a href="mailto:janith3000@gmail.com">Janith Bandara</a>
 * @author Thebora Kompanioni https://github.com/theborakompanioni
 */
public class DatabaseAuditHandler extends Handler {

	/**
	 * The Constant serialVersionUID.
	 */
	private static final long serialVersionUID = -4994028889410866952L;

	private static final String DEFAULT_TABLE_NAME = "audit";

	/**
	 * Creating cache for Data access objects for different tables.
	 */
	private final LoadingCache<String, AuditLogDao> daos = CacheBuilder.newBuilder().maximumSize(1000).expireAfterAccess(15, TimeUnit.MINUTES).build(new CacheLoader<String, AuditLogDao>() {

		@Override
		public AuditLogDao load(final String tableName) throws HandlerException {

			return new AuditLogDaoImpl(tableName, DatabaseAuditHandler.this.schema);
		}
	});

	/**
	 * The embeded.
	 */
	private String embedded;

	/**
	 * The db_driver.
	 */
	private String db_driver;

	/**
	 * The db_url.
	 */
	private String db_url;

	/**
	 * The db_user.
	 */
	private String db_user;

	/**
	 * The db_password.
	 */
	private String db_password;

	/**
	 * The db_connection_type.
	 */
	private String db_connection_type;

	/**
	 * The db_datasource class.
	 */
	private String db_datasourceClass;

	/**
	 * The db_jndi_datasource.
	 */
	private String db_jndi_datasource;

	/**
	 * The auto commit.
	 */
	private boolean db_pool_autoCommit = true;

	/**
	 * The connection timeout.
	 */
	private Long db_pool_connectionTimeout;

	/**
	 * The idle timeout.
	 */
	private Integer db_pool_idleTimeout;

	/**
	 * The max lifetime.
	 */
	private Integer db_pool_maxLifetime;

	/**
	 * The minimum idle.
	 */
	private Integer db_pool_minimumIdle;

	/**
	 * The maximum pool size.
	 */
	private Integer db_pool_maximumPoolSize;

	/**
	 * The Constant POOLED_CONNECTION.
	 */
	private static final String POOLED_CONNECTION = "pooled";

	/**
	 * The Constant JNDI_CONNECTION.
	 */
	private static final String JNDI_CONNECTION = "jndi";

	/**
	 * The server.
	 */
	private EmbededDBServer server;

	/**
	 * The factory.
	 */
	private ConnectionFactory factory;

	/**
	 * The separate.
	 */
	private boolean separate = false;

	/**
	 * The data source.
	 */
	private DataSource dataSource;

	/**
	 * The table_prefix.
	 */
	private String table_prefix;

	/**
	 * The table_suffix.
	 */
	private String table_suffix = "audit";

	/**
	 * The default_table_suffix.
	 */
	private String default_table_name = DEFAULT_TABLE_NAME;

	/**
	 * The default_table_suffix.
	 */
	private String schema;

	/**
	 * Instantiates a new database audit handler.
	 */
	public DatabaseAuditHandler() {
	}

	/**
	 * Initialize database handler.
	 *
	 * @throws InitializationException
	 *             the initialization exception
	 */
	@Override
	public void init() throws InitializationException {

		if ((null == this.embedded) || "true".equalsIgnoreCase(this.embedded)) {
			Log.warn("Audit4j Database Handler runs on embedded mode. See " + ErrorGuide.ERROR_URL + "embeddeddb for further details.");
			this.server = HSQLEmbededDBServer.getInstance();
			this.db_driver = this.server.getDriver();
			this.db_url = this.server.getNetworkProtocol() + ":file:audit4jdb";
			if (this.db_user == null) {
				this.db_user = Utils.EMBEDED_DB_USER;
			}
			if (this.db_password == null) {
				this.db_password = Utils.EMBEDED_DB_PASSWORD;
			}
			this.server.setUname(this.db_user);
			this.server.setPassword(this.db_password);
			this.server.start();
		}

		this.factory = ConnectionFactory.getInstance();
		this.factory.setDataSource(this.dataSource);
		this.factory.setDriver(this.getDb_driver());
		this.factory.setUrl(this.getDb_url());
		this.factory.setUser(this.getDb_user());
		this.factory.setPassword(this.getDb_password());

		this.factory.setDataSourceClass(this.db_datasourceClass);
		this.factory.setAutoCommit(this.db_pool_autoCommit);
		if (this.db_pool_connectionTimeout != null) {
			this.factory.setConnectionTimeout(this.db_pool_connectionTimeout);
		}
		if (this.db_pool_idleTimeout != null) {
			this.factory.setIdleTimeout(this.db_pool_idleTimeout);
		}
		if (this.db_pool_maximumPoolSize != null) {
			this.factory.setMaximumPoolSize(this.db_pool_maximumPoolSize);
		}
		if (this.db_pool_maxLifetime != null) {
			this.factory.setMaxLifetime(this.db_pool_maxLifetime);
		}
		if (this.db_pool_minimumIdle != null) {
			this.factory.setMinimumIdle(this.db_pool_minimumIdle);
		}

		if ((this.getDb_connection_type() != null) && this.getDb_connection_type().equals(POOLED_CONNECTION)) {
			this.factory.setConnectionType(ConnectionType.POOLED);
		}
		else if ((this.getDb_connection_type() != null) && this.getDb_connection_type().equals(JNDI_CONNECTION)) {
			this.factory.setConnectionType(ConnectionType.JNDI);
			this.factory.setJndiDataSource(this.getDb_jndi_datasource());
		}
		else {
			this.factory.setConnectionType(ConnectionType.SINGLE);
		}

		this.factory.init();

		try {
			this.getDaoForTable(this.default_table_name);
		}
		catch (final HandlerException e) {
			throw new InitializationException("Unable to create tables", e);
		}

	}

	/**
	 * Handle event.
	 * <p>
	 * {@inheritDoc}
	 *
	 * @see org.audit4j.core.handler.Handler#handle()
	 */
	@Override
	public void handle() throws HandlerException {

		final String repository = this.getAuditEvent().getRepository();
		final boolean writeInDefaultTable = !this.separate || (repository == null);
		final String tableName = writeInDefaultTable ? this.default_table_name : this.generateTableName(repository);

		this.getDaoForTable(tableName).writeEvent(this.getAuditEvent());
	}

	@Override
	public List<AuditEvent> findAuditEventsByActor(final String actor, final Integer limit, final String repository) throws HandlerException {

		final boolean writeInDefaultTable = !this.separate || (repository == null);
		final String tableName = writeInDefaultTable ? this.default_table_name : this.generateTableName(repository);

		return this.getDaoForTable(tableName).findAuditEventsByActor(actor, limit);
	}

	@Override
	public boolean implementsSearch() {

		return true;
	}

	/**
	 * Shutdown database handler.
	 */
	@Override
	public void stop() {

		this.factory.stop();
		if (this.server != null) {
			this.server.shutdown();
		}
	}

	/**
	 * Generate table name.
	 *
	 * @param repository
	 * @return the string
	 */
	private String generateTableName(final String repository) {

		if (this.table_prefix == null) {
			return repository + "_" + this.table_suffix;
		}
		return this.table_prefix + "_" + repository + "_" + this.table_suffix;
	}

	private AuditLogDao getDaoForTable(final String tableName) throws HandlerException {

		try {
			return this.daos.get(tableName);
		}
		catch (final ExecutionException e) {
			Throwables.propagateIfInstanceOf(e.getCause(), HandlerException.class);
			throw new HandlerException("Execution Exception", DatabaseAuditHandler.class, e);
		}
	}

	/**
	 * Gets the db_connection_type.
	 *
	 * @return the db_connection_type
	 */
	public String getDb_connection_type() {

		return this.db_connection_type;
	}

	/**
	 * Sets the db_connection_type.
	 *
	 * @param db_connection_type
	 *            the new db_connection_type
	 */
	public void setDb_connection_type(final String db_connection_type) {

		this.db_connection_type = db_connection_type;
	}

	/**
	 * Gets the embedded.
	 *
	 * @return the embedded
	 */
	public String getEmbedded() {

		return this.embedded;
	}

	/**
	 * Sets the embedded.
	 *
	 * @param embedded
	 *            the new embedded
	 */
	public void setEmbedded(final String embedded) {

		this.embedded = embedded;
	}

	/**
	 * Gets the db_driver.
	 *
	 * @return the db_driver
	 */
	public String getDb_driver() {

		return this.db_driver;
	}

	/**
	 * Sets the db_driver.
	 *
	 * @param db_driver
	 *            the new db_driver
	 */
	public void setDb_driver(final String db_driver) {

		this.db_driver = db_driver;
	}

	/**
	 * Gets the db_url.
	 *
	 * @return the db_url
	 */
	public String getDb_url() {

		return this.db_url;
	}

	/**
	 * Sets the db_url.
	 *
	 * @param db_url
	 *            the new db_url
	 */
	public void setDb_url(final String db_url) {

		this.db_url = db_url;
	}

	/**
	 * Gets the db_user.
	 *
	 * @return the db_user
	 */
	public String getDb_user() {

		return this.db_user;
	}

	/**
	 * Sets the db_user.
	 *
	 * @param db_user
	 *            the new db_user
	 */
	public void setDb_user(final String db_user) {

		this.db_user = db_user;
	}

	/**
	 * Gets the db_password.
	 *
	 * @return the db_password
	 */
	public String getDb_password() {

		return this.db_password;
	}

	/**
	 * Sets the db_password.
	 *
	 * @param db_password
	 *            the new db_password
	 */
	public void setDb_password(final String db_password) {

		this.db_password = db_password;
	}

	/**
	 * Gets the db_jndi_datasource.
	 *
	 * @return the db_jndi_datasource
	 */
	public String getDb_jndi_datasource() {

		return this.db_jndi_datasource;
	}

	/**
	 * Sets the db_jndi_datasource.
	 *
	 * @param db_jndi_datasource
	 *            the new db_jndi_datasource
	 */
	public void setDb_jndi_datasource(final String db_jndi_datasource) {

		this.db_jndi_datasource = db_jndi_datasource;
	}

	/**
	 * Sets the separate.
	 *
	 * @param separate
	 *            the new separate
	 */
	public void setSeparate(final boolean separate) {

		this.separate = separate;
	}

	/**
	 * Sets the data source.
	 *
	 * @param dataSource
	 *            the new data source
	 */
	public void setDataSource(final DataSource dataSource) {

		this.dataSource = dataSource;
	}

	/**
	 * Sets the table_prefix.
	 *
	 * @param table_prefix
	 *            the new table_prefix
	 */
	public void setTable_prefix(final String table_prefix) {

		this.table_prefix = table_prefix;
	}

	/**
	 * Sets the table_suffix.
	 *
	 * @param table_suffix
	 *            the new table_suffix
	 */
	public void setTable_suffix(final String table_suffix) {

		this.table_suffix = table_suffix;
	}

	/**
	 * Sets the default_table_name.
	 *
	 * @param default_table_name
	 *            the new default_table_name
	 */
	public void setDefault_table_name(final String default_table_name) {

		this.default_table_name = checkNotEmpty(default_table_name, "Table name must not be empty");
	}

	/**
	 * Sets the db_pool_auto commit.
	 *
	 * @param db_pool_autoCommit
	 *            the new db_pool_auto commit
	 */
	public void setDb_pool_autoCommit(final boolean db_pool_autoCommit) {

		this.db_pool_autoCommit = db_pool_autoCommit;
	}

	/**
	 * Sets the db_pool_connection timeout.
	 *
	 * @param db_pool_connectionTimeout
	 *            the new db_pool_connection timeout
	 */
	public void setDb_pool_connectionTimeout(final Long db_pool_connectionTimeout) {

		this.db_pool_connectionTimeout = db_pool_connectionTimeout;
	}

	/**
	 * Sets the db_pool_idle timeout.
	 *
	 * @param db_pool_idleTimeout
	 *            the new db_pool_idle timeout
	 */
	public void setDb_pool_idleTimeout(final Integer db_pool_idleTimeout) {

		this.db_pool_idleTimeout = db_pool_idleTimeout;
	}

	/**
	 * Sets the db_pool_max lifetime.
	 *
	 * @param db_pool_maxLifetime
	 *            the new db_pool_max lifetime
	 */
	public void setDb_pool_maxLifetime(final Integer db_pool_maxLifetime) {

		this.db_pool_maxLifetime = db_pool_maxLifetime;
	}

	/**
	 * Sets the db_pool_minimum idle.
	 *
	 * @param db_pool_minimumIdle
	 *            the new db_pool_minimum idle
	 */
	public void setDb_pool_minimumIdle(final Integer db_pool_minimumIdle) {

		this.db_pool_minimumIdle = db_pool_minimumIdle;
	}

	/**
	 * Sets the db_pool_maximum pool size.
	 *
	 * @param db_pool_maximumPoolSize
	 *            the new db_pool_maximum pool size
	 */
	public void setDb_pool_maximumPoolSize(final Integer db_pool_maximumPoolSize) {

		this.db_pool_maximumPoolSize = db_pool_maximumPoolSize;
	}

	/**
	 * Sets the db_datasource class.
	 *
	 * @param db_datasourceClass
	 *            the new db_datasource class
	 */
	public void setDb_datasourceClass(final String db_datasourceClass) {

		this.db_datasourceClass = db_datasourceClass;
	}

	public String getTable_suffix() {

		return this.table_suffix;
	}

	public String getTable_prefix() {

		return this.table_prefix;
	}

	public String getDefault_table_name() {

		return this.default_table_name;
	}

	public String getSchema() {

		return this.schema;
	}

	public void setSchema(final String schema) {

		this.schema = schema;
	}

	public boolean getSeparate() {

		return this.separate;
	}

	public boolean getDb_pool_autoCommit() {

		return this.db_pool_autoCommit;
	}

	public Long getDb_pool_connectionTimeout() {

		return this.db_pool_connectionTimeout;
	}

	public Integer getDb_pool_idleTimeout() {

		return this.db_pool_idleTimeout;
	}

	public Integer getDb_pool_maxLifetime() {

		return this.db_pool_maxLifetime;
	}

	public Integer getDb_pool_minimumIdle() {

		return this.db_pool_minimumIdle;
	}

	public Integer getDb_pool_maximumPoolSize() {

		return this.db_pool_maximumPoolSize;
	}

	public String getDb_datasourceClass() {

		return this.db_datasourceClass;
	}

}
