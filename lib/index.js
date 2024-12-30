const { DynamoDBClient, CreateTableCommand, waitUntilTableExists } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, DeleteCommand, QueryCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');
const bcrypt = require('bcryptjs');
const { EventEmitter } = require('events');
const SALT_ROUNDS = 10;

class ErrsoleDynamoDB extends EventEmitter {
  constructor (options = {}) {
    super();

    const region = options.region;
    let credentials;
    if (options.accessKeyId && options.secretAccessKey) {
      credentials = {
        accessKeyId: options.accessKeyId,
        secretAccessKey: options.secretAccessKey
      };
    }

    this.tablePrefix = (options.tablePrefix || 'errsole').toLowerCase().replace(/[^a-zA-Z0-9]/g, '');

    this.usersTable = `${this.tablePrefix}_users`;
    this.configTable = `${this.tablePrefix}_config`;
    this.notificationsTable = `${this.tablePrefix}_notifications`;
    this.logsTable = `${this.tablePrefix}_logs`; // Logs Table

    this.name = require('../package.json').name;
    this.version = require('../package.json').version || '0.0.0';

    this.dynamoDBClient = new DynamoDBClient({ region, credentials });
    this.documentClient = DynamoDBDocumentClient.from(this.dynamoDBClient);

    this.pendingLogs = [];
    this.batchSize = 100;
    this.flushInterval = 1000;

    this.init();
  }

  async init () {
    await this.createDynamoDBTables();
    await this.ensureLogsTTL();
    this.emit('ready');
    setInterval(() => this.flushLogs(), this.flushInterval);
  }

  async createDynamoDBTables () {
    const tablesConfig = [
      {
        TableName: this.usersTable,
        KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
        AttributeDefinitions: [
          { AttributeName: 'id', AttributeType: 'S' },
          { AttributeName: 'email', AttributeType: 'S' }
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'email-index',
            KeySchema: [{ AttributeName: 'email', KeyType: 'HASH' }],
            Projection: { ProjectionType: 'ALL' }
          }
        ],
        BillingMode: 'PAY_PER_REQUEST'
      },
      {
        TableName: this.configTable,
        KeySchema: [{ AttributeName: 'key', KeyType: 'HASH' }],
        AttributeDefinitions: [{ AttributeName: 'key', AttributeType: 'S' }],
        BillingMode: 'PAY_PER_REQUEST'
      },
      {
        TableName: this.notificationsTable,
        KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
        AttributeDefinitions: [
          { AttributeName: 'id', AttributeType: 'N' },
          { AttributeName: 'hostname', AttributeType: 'S' },
          { AttributeName: 'hashed_message', AttributeType: 'S' },
          { AttributeName: 'created_at', AttributeType: 'N' }
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'hostname-hashed_message-index',
            KeySchema: [
              { AttributeName: 'hostname', KeyType: 'HASH' },
              { AttributeName: 'hashed_message', KeyType: 'RANGE' }
            ],
            Projection: { ProjectionType: 'ALL' }
          },
          {
            IndexName: 'created_at-index',
            KeySchema: [{ AttributeName: 'created_at', KeyType: 'HASH' }],
            Projection: { ProjectionType: 'ALL' }
          }
        ],
        BillingMode: 'PAY_PER_REQUEST'
      },
      {
        TableName: this.logsTable, // Logs Table
        KeySchema: [
          { AttributeName: 'id', KeyType: 'HASH' } // Partition Key
        ],
        AttributeDefinitions: [
          { AttributeName: 'id', AttributeType: 'S' },
          { AttributeName: 'source', AttributeType: 'S' },
          { AttributeName: 'level', AttributeType: 'S' },
          { AttributeName: 'timestamp', AttributeType: 'S' }, // Change to 'S' for formatted timestamps
          { AttributeName: 'hostname', AttributeType: 'S' },
          { AttributeName: 'pid', AttributeType: 'N' },
          { AttributeName: 'errsole_id', AttributeType: 'N' }
        ],
        BillingMode: 'PAY_PER_REQUEST',
        GlobalSecondaryIndexes: [
          {
            IndexName: 'source-level-id-index',
            KeySchema: [
              { AttributeName: 'source', KeyType: 'HASH' },
              { AttributeName: 'level', KeyType: 'RANGE' }
            ],
            Projection: { ProjectionType: 'ALL' }
          },
          {
            IndexName: 'source-level-timestamp-index',
            KeySchema: [
              { AttributeName: 'source', KeyType: 'HASH' },
              { AttributeName: 'timestamp', KeyType: 'RANGE' }
            ],
            Projection: { ProjectionType: 'ALL' }
          },
          {
            IndexName: 'hostname-pid-id-index',
            KeySchema: [
              { AttributeName: 'hostname', KeyType: 'HASH' },
              { AttributeName: 'pid', KeyType: 'RANGE' }
            ],
            Projection: { ProjectionType: 'ALL' }
          },
          {
            IndexName: 'errsole_id-index',
            KeySchema: [
              { AttributeName: 'errsole_id', KeyType: 'HASH' }
            ],
            Projection: { ProjectionType: 'ALL' }
          }
        ]
      }
    ];

    for (const tableConfig of tablesConfig) {
      try {
        await this.dynamoDBClient.send(new CreateTableCommand(tableConfig));
      } catch (err) {
        if (err.name !== 'ResourceInUseException') throw err;
      }
    }

    for (const tableConfig of tablesConfig) {
      await waitUntilTableExists({ client: this.dynamoDBClient }, { TableName: tableConfig.TableName });
    }
  }

  async ensureLogsTTL () {
    const DEFAULT_LOGS_TTL = 30 * 24 * 60 * 60 * 1000;
    const configResult = await this.getConfig('logsTTL');
    if (!configResult.item) {
      await this.setConfig('logsTTL', DEFAULT_LOGS_TTL.toString());
    }
  }

  async getConfig (key) {
    const params = {
      TableName: this.configTable,
      Key: { key }
    };
    const response = await this.documentClient.send(new GetCommand(params));
    const item = response.Item || null;
    return { item };
  }

  async setConfig (key, value) {
    const params = {
      TableName: this.configTable,
      Item: { key, value }
    };
    await this.documentClient.send(new PutCommand(params));
    return await this.getConfig(key);
  }

  async deleteConfig (key) {
    const params = {
      TableName: this.configTable,
      Key: { key }
    };
    await this.documentClient.send(new DeleteCommand(params));
    return {};
  }

  postLogs (logEntries) {
    this.pendingLogs.push(...logEntries);
    if (this.pendingLogs.length >= this.batchSize) {
      this.flushLogs().catch(console.error);
    }
    return {};
  }

  async flushLogs () {
    const logsToPost = this.pendingLogs.splice(0, this.pendingLogs.length);
    if (logsToPost.length === 0) {
      return {};
    }

    try {
      const insertPromises = logsToPost.map(log => {
        let timestamp;
        if (log.timestamp instanceof Date) {
          timestamp = log.timestamp.toISOString();
        } else if (typeof log.timestamp === 'string') {
          const parsedDate = new Date(log.timestamp);
          if (!isNaN(parsedDate)) {
            timestamp = parsedDate.toISOString();
          } else {
            throw new Error(`Invalid timestamp: ${log.timestamp}`);
          }
        } else {
          timestamp = new Date().toISOString();
        }

        const params = {
          TableName: this.logsTable,
          Item: {
            id: `${Date.now()}${Math.floor(10000 + Math.random() * 90000)}`,
            timestamp,
            hostname: log.hostname,
            pid: log.pid,
            source: log.source,
            level: log.level,
            message: log.message,
            meta: log.meta,
            errsole_id: log.errsole_id
          }
        };

        return this.documentClient.send(new PutCommand(params));
      });

      await Promise.all(insertPromises);
    } catch (error) {
    }
  }

  async getHostnames () {
    const params = {
      TableName: this.logsTable,
      ProjectionExpression: 'hostname', // Fetch only the hostname field
      FilterExpression: 'attribute_exists(hostname) AND hostname <> :empty',
      ExpressionAttributeValues: {
        ':empty': ''
      }
    };

    return new Promise((resolve, reject) => {
      const hostnames = new Set();
      const scan = (ExclusiveStartKey) => {
        this.documentClient.send(new ScanCommand({ ...params, ExclusiveStartKey }))
          .then(result => {
            result.Items.forEach(item => {
              if (item.hostname) hostnames.add(item.hostname);
            });

            if (result.LastEvaluatedKey) {
              scan(result.LastEvaluatedKey); // Continue scanning if more results exist
            } else {
              resolve({ items: Array.from(hostnames).sort() }); // Sort and resolve when scanning is complete
            }
          })
          .catch(err => reject(err)); // Reject if an error occurs
      };

      scan(); // Start the scan operation
    });
  }

  async getLogs (filters = {}) {
    const DEFAULT_LOGS_LIMIT = 100;
    filters.limit = filters.limit || DEFAULT_LOGS_LIMIT;

    const filterExpressions = [];
    const expressionValues = {};
    const expressionAttributeNames = {
      '#id': 'id',
      '#hostname': 'hostname',
      '#errsole_id': 'errsole_id',
      '#level': 'level',
      '#timestamp': 'timestamp',
      '#pid': 'pid',
      '#source': 'source',
      '#message': 'message'
    };

    if (filters.hostname) {
      filterExpressions.push('#hostname = :hostname');
      expressionValues[':hostname'] = filters.hostname;
    }
    if (filters.pid) {
      filterExpressions.push('#pid = :pid');
      expressionValues[':pid'] = filters.pid;
    }
    if (filters.sources && filters.sources.length > 0) {
      const sourcesCondition = filters.sources.map((source, index) => {
        const placeholder = `:source${index}`;
        expressionValues[placeholder] = source;
        return `#source = ${placeholder}`;
      }).join(' OR ');
      filterExpressions.push(sourcesCondition); // Removed redundant parentheses
    }
    if (filters.levels && filters.levels.length > 0) {
      const levelsCondition = filters.levels.map((level, index) => {
        const placeholder = `:level${index}`;
        expressionValues[placeholder] = level;
        return `#level = ${placeholder}`;
      }).join(' OR ');
      filterExpressions.push(levelsCondition); // Removed redundant parentheses
    }

    if (filters.hostnames && filters.hostnames.length > 0) {
      const hostnamePlaceholders = filters.hostnames.map((_, index) => `:hostname${index}`);
      filterExpressions.push(`#hostname IN (${hostnamePlaceholders.join(', ')})`);
      filters.hostnames.forEach((hostname, index) => {
        expressionValues[`:hostname${index}`] = hostname;
      });
    }

    // Add logic for level_json and errsole_id
    if (filters.level_json || filters.errsole_id) {
      const orConditions = [];

      if (filters.level_json && filters.level_json.length > 0) {
        const levelJsonConditions = filters.level_json.map((levelObj, index) => {
          const sourcePlaceholder = `:source${index}`;
          const levelPlaceholder = `:level_json${index}`;
          expressionValues[sourcePlaceholder] = levelObj.source;
          expressionValues[levelPlaceholder] = levelObj.level;
          return `(#source = ${sourcePlaceholder} AND #level = ${levelPlaceholder})`;
        }).join(' OR ');
        orConditions.push(levelJsonConditions);
      }

      if (filters.errsole_id) {
        orConditions.push('#errsole_id = :errsole_id');
        expressionValues[':errsole_id'] = filters.errsole_id;
      }

      filterExpressions.push(orConditions.join(' OR '));
    }

    if (filters.lt_id) {
      filterExpressions.push('#id < :lt_id');
      expressionValues[':lt_id'] = filters.lt_id;
    } else if (filters.gt_id) {
      filterExpressions.push('#id > :gt_id');
      expressionValues[':gt_id'] = filters.gt_id;
    } else if (filters.lte_timestamp || filters.gte_timestamp) {
      if (filters.lte_timestamp) {
        filterExpressions.push('#timestamp <= :lte_timestamp');
        expressionValues[':lte_timestamp'] = new Date(filters.lte_timestamp).toISOString();
      }
      if (filters.gte_timestamp) {
        filterExpressions.push('#timestamp >= :gte_timestamp');
        expressionValues[':gte_timestamp'] = new Date(filters.gte_timestamp).toISOString();
      }
    }

    const params = {
      TableName: this.logsTable,
      FilterExpression: filterExpressions.length ? filterExpressions.join(' AND ') : undefined,
      ExpressionAttributeValues: Object.keys(expressionValues).length ? expressionValues : undefined,
      ExpressionAttributeNames: Object.keys(expressionAttributeNames).length ? expressionAttributeNames : undefined,
      ProjectionExpression: '#id, #hostname, #errsole_id, #level, #timestamp, #pid, #source, #message', // Exclude meta
      Limit: filters.limit
    };

    try {
      const data = await this.documentClient.send(new ScanCommand(params));
      const results = data.Items || [];
      results.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      return { items: results };
    } catch (error) {
      console.error('Error fetching logs:', error);
      throw error;
    }
  }

  async searchLogs (searchTerms, filters = {}) {
    const DEFAULT_LOGS_LIMIT = 100;
    filters.limit = filters.limit || DEFAULT_LOGS_LIMIT;

    const filterExpressions = [];
    const expressionValues = {};
    const expressionAttributeNames = {
      '#id': 'id',
      '#hostname': 'hostname',
      '#errsole_id': 'errsole_id',
      '#level': 'level',
      '#timestamp': 'timestamp',
      '#pid': 'pid',
      '#source': 'source',
      '#message': 'message'
    };

    // Add search terms for the `message` field
    if (searchTerms && searchTerms.length > 0) {
      const searchConditions = searchTerms.map((term, index) => {
        const placeholder = `:searchTerm${index}`;
        expressionValues[placeholder] = term;
        return `contains(#message, ${placeholder})`;
      }).join(' AND ');
      filterExpressions.push(`(${searchConditions})`);
    }

    // Add hostname filter
    if (filters.hostname) {
      filterExpressions.push('#hostname = :hostname');
      expressionValues[':hostname'] = filters.hostname;
    }

    if (filters.pid) {
      filterExpressions.push('#pid = :pid');
      expressionValues[':pid'] = filters.pid;
    }

    if (filters.sources && filters.sources.length > 0) {
      const sourcesCondition = filters.sources.map((source, index) => {
        const placeholder = `:source${index}`;
        expressionValues[placeholder] = source;
        return `#source = ${placeholder}`;
      }).join(' OR ');
      filterExpressions.push(`(${sourcesCondition})`);
    }

    if (filters.levels && filters.levels.length > 0) {
      const levelsCondition = filters.levels.map((level, index) => {
        const placeholder = `:level${index}`;
        expressionValues[placeholder] = level;
        return `#level = ${placeholder}`;
      }).join(' OR ');
      filterExpressions.push(`(${levelsCondition})`);
    }

    if (filters.hostnames && filters.hostnames.length > 0) {
      const hostnamePlaceholders = filters.hostnames.map((_, index) => `:hostname${index}`);
      filterExpressions.push(`#hostname IN (${hostnamePlaceholders.join(', ')})`);
      filters.hostnames.forEach((hostname, index) => {
        expressionValues[`:hostname${index}`] = hostname;
      });
    }

    if (filters.level_json || filters.errsole_id) {
      const orConditions = [];

      if (filters.level_json && filters.level_json.length > 0) {
        const levelJsonConditions = filters.level_json.map((levelObj, index) => {
          const sourcePlaceholder = `:source${index}`;
          const levelPlaceholder = `:level_json${index}`;
          expressionValues[sourcePlaceholder] = levelObj.source;
          expressionValues[levelPlaceholder] = levelObj.level;
          return `(#source = ${sourcePlaceholder} AND #level = ${levelPlaceholder})`;
        }).join(' OR ');
        orConditions.push(levelJsonConditions);
      }

      if (filters.errsole_id) {
        orConditions.push('#errsole_id = :errsole_id');
        expressionValues[':errsole_id'] = filters.errsole_id;
      }

      if (orConditions.length > 0) {
        filterExpressions.push(`(${orConditions.join(' OR ')})`);
      }
    }

    if (filters.lt_id) {
      filterExpressions.push('#id < :lt_id');
      expressionValues[':lt_id'] = filters.lt_id;
    } else if (filters.gt_id) {
      filterExpressions.push('#id > :gt_id');
      expressionValues[':gt_id'] = filters.gt_id;
    } else if (filters.lte_timestamp || filters.gte_timestamp) {
      if (filters.lte_timestamp) {
        filterExpressions.push('#timestamp <= :lte_timestamp');
        expressionValues[':lte_timestamp'] = new Date(filters.lte_timestamp).toISOString();
      }
      if (filters.gte_timestamp) {
        filterExpressions.push('#timestamp >= :gte_timestamp');
        expressionValues[':gte_timestamp'] = new Date(filters.gte_timestamp).toISOString();
      }
      if (filters.lte_timestamp && !filters.gte_timestamp) {
        filters.lte_timestamp = new Date(filters.lte_timestamp);
        const gteTimestamp = new Date(filters.lte_timestamp.getTime() - 24 * 60 * 60 * 1000);
        filterExpressions.push('#timestamp >= :gte_timestamp');
        expressionValues[':gte_timestamp'] = gteTimestamp.toISOString();
        filters.gte_timestamp = gteTimestamp;
      }

      if (filters.gte_timestamp && !filters.lte_timestamp) {
        filters.gte_timestamp = new Date(filters.gte_timestamp);
        const lteTimestamp = new Date(filters.gte_timestamp.getTime() + 24 * 60 * 60 * 1000);
        filterExpressions.push('#timestamp <= :lte_timestamp');
        expressionValues[':lte_timestamp'] = lteTimestamp.toISOString();
        filters.lte_timestamp = lteTimestamp;
      }
    }

    const params = {
      TableName: this.logsTable,
      FilterExpression: filterExpressions.length ? filterExpressions.join(' AND ') : undefined,
      ExpressionAttributeValues: Object.keys(expressionValues).length ? expressionValues : undefined,
      ExpressionAttributeNames: Object.keys(expressionAttributeNames).length ? expressionAttributeNames : undefined,
      ProjectionExpression: '#id, #hostname, #errsole_id, #level, #timestamp, #pid, #source, #message',
      Limit: filters.limit
    };

    try {
      const data = await this.documentClient.send(new ScanCommand(params));
      const results = data.Items || [];
      results.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      return { items: results };
    } catch (error) {
      console.error('Error fetching logs:', error);
      throw error;
    }
  }

  async getMeta (id) {
    const params = {
      TableName: this.logsTable,
      Key: { id },
      ProjectionExpression: 'id, meta'
    };

    return new Promise((resolve, reject) => {
      this.documentClient.send(new GetCommand(params), (err, result) => {
        if (err) {
          // console.error('Error fetching metadata:', err);
          return reject(err);
        }
        if (!result.Item) {
          return reject(new Error('Log entry not found.'));
        }
        resolve({ item: result.Item });
      });
    });
  }

  async insertNotificationItem (notification = {}) {
    const errsoleId = String(notification.errsole_id);

    const hostname = notification.hostname;
    const hashedMessage = notification.hashed_message;
    const queryParams = {
      TableName: this.notificationsTable,
      IndexName: 'hostname-hashed_message-index',
      KeyConditionExpression: 'hostname = :host AND hashed_message = :hash',
      ExpressionAttributeValues: {
        ':host': hostname,
        ':hash': hashedMessage
      }
    };

    let previousNotificationItem = null;
    try {
      const queryResult = await this.documentClient.send(new QueryCommand(queryParams));
      if (queryResult.Items && queryResult.Items.length > 0) {
        queryResult.Items.sort((a, b) => b.created_at - a.created_at);
        previousNotificationItem = queryResult.Items[0];
      }
    } catch (err) {
      console.error('Error fetching previous notification:', err);
      throw err;
    }

    const threeDigitRandom = Math.floor(Math.random() * 900) + 100;
    const newId = `${Date.now()}${threeDigitRandom}`;

    const nowTimestamp = Date.now();

    const newItem = {
      id: newId,
      errsole_id: errsoleId,
      hostname,
      hashed_message: hashedMessage,
      created_at: nowTimestamp
    };

    try {
      await this.documentClient.send(new PutCommand({
        TableName: this.notificationsTable,
        Item: newItem
      }));
    } catch (err) {
      console.error('Error inserting new notification:', err);
      throw err;
    }

    const startOfDayUTC = new Date();
    startOfDayUTC.setUTCHours(0, 0, 0, 0);
    const endOfDayUTC = new Date();
    endOfDayUTC.setUTCHours(23, 59, 59, 999);

    const scanParams = {
      TableName: this.notificationsTable,
      FilterExpression: 'hashed_message = :hash AND created_at BETWEEN :start AND :end',
      ExpressionAttributeValues: {
        ':hash': hashedMessage,
        ':start': startOfDayUTC.getTime(),
        ':end': endOfDayUTC.getTime()
      },
      Select: 'COUNT'
    };

    let todayNotificationCount = 0;
    try {
      const scanResult = await this.documentClient.send(new ScanCommand(scanParams));
      todayNotificationCount = scanResult.Count || 0;
    } catch (err) {
      console.error('Error counting notifications today:', err);
      throw err;
    }

    return {
      previousNotificationItem,
      todayNotificationCount
    };
  }

  async createUser (user) {
    const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS);
    const emailCheckParams = {
      TableName: this.usersTable,
      IndexName: 'email-index',
      KeyConditionExpression: '#email = :email',
      ExpressionAttributeNames: {
        '#email': 'email'
      },
      ExpressionAttributeValues: {
        ':email': user.email
      }
    };

    try {
      const existingUser = await this.documentClient.send(new QueryCommand(emailCheckParams));

      if (existingUser.Items && existingUser.Items.length > 0) {
        throw new Error('A user with the provided email already exists.');
      }

      const params = {
        TableName: this.usersTable,
        Item: {
          id: Date.now().toString(), // Unique identifier
          name: user.name,
          email: user.email,
          hashed_password: hashedPassword,
          role: user.role
        }
      };

      await this.documentClient.send(new PutCommand(params));

      return {
        item: {
          id: params.Item.id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      };
    } catch (error) {
      return error;
    }
  }

  async verifyUser (email, password) {
    if (!email || !password) {
      throw new Error('Both email and password are required for verification.');
    }

    const params = {
      TableName: this.usersTable,
      IndexName: 'email-index',
      KeyConditionExpression: '#email = :email',
      ExpressionAttributeNames: {
        '#email': 'email'
      },
      ExpressionAttributeValues: {
        ':email': email
      }
    };

    try {
      const result = await this.documentClient.send(new QueryCommand(params));

      if (!result.Items || result.Items.length === 0) {
        throw new Error('User not found.');
      }

      const user = result.Items[0];

      const isPasswordCorrect = await bcrypt.compare(password, user.hashed_password);
      if (!isPasswordCorrect) {
        throw new Error('Incorrect password.');
      }

      delete user.hashed_password;
      return { item: user };
    } catch (error) {
      console.error('Error verifying user:', error);
      throw error;
    }
  }

  async getUserCount () {
    const params = {
      TableName: this.usersTable,
      Select: 'COUNT' // This will count all items in the table
    };

    return new Promise((resolve, reject) => {
      this.documentClient.send(new ScanCommand(params))
        .then(result => {
          resolve({ count: result.Count || 0 }); // Return the count
        })
        .catch(err => {
          reject(err); // Reject with the error
        });
    });
  }

  async getAllUsers () {
    const params = {
      TableName: this.usersTable, // The table name
      ProjectionExpression: '#id, #name, #email, #role', // Specify the fields to retrieve
      ExpressionAttributeNames: {
        '#id': 'id',
        '#name': 'name',
        '#email': 'email',
        '#role': 'role'
      }
    };

    return new Promise((resolve, reject) => {
      this.documentClient.send(new ScanCommand(params))
        .then(result => {
          resolve({ items: result.Items || [] }); // Return the retrieved users
        })
        .catch(err => {
          reject(err); // Reject with the error
        });
    });
  }

  async getUserByEmail (email) {
    if (!email) throw new Error('Email is required.');

    const params = {
      TableName: this.usersTable,
      IndexName: 'email-index', // Use the GSI for email
      KeyConditionExpression: '#email = :email',
      ExpressionAttributeNames: {
        '#email': 'email' // Alias for the email attribute
      },
      ExpressionAttributeValues: {
        ':email': email // Value to search for
      }
    };

    return new Promise((resolve, reject) => {
      this.documentClient.send(new QueryCommand(params))
        .then(result => {
          if (!result.Items || result.Items.length === 0) {
            return reject(new Error('User not found.'));
          }
          resolve({ item: result.Items[0] }); // Return the first matching user
        })
        .catch(err => {
          reject(err); // Reject with the error
        });
    });
  }

  async updateUserByEmail (email, updates) {
    if (!email) throw new Error('Email is required.');
    if (!updates || Object.keys(updates).length === 0) throw new Error('No updates provided.');

    const restrictedFields = ['id', 'hashed_password'];
    restrictedFields.forEach(field => delete updates[field]);

    if (Object.keys(updates).length === 0) throw new Error('No valid updates provided.');

    // Step 1: Query the user by email
    const queryParams = {
      TableName: this.usersTable,
      IndexName: 'email-index', // Use the GSI for email
      KeyConditionExpression: '#email = :email',
      ExpressionAttributeNames: {
        '#email': 'email'
      },
      ExpressionAttributeValues: {
        ':email': email
      }
    };

    const userResult = await this.documentClient.send(new QueryCommand(queryParams));

    if (!userResult.Items || userResult.Items.length === 0) {
      throw new Error('User not found.');
    }

    const user = userResult.Items[0]; // Get the user record

    // Step 2: Update the user by ID (primary key)
    const updateExpression = [];
    const expressionAttributeNames = {};
    const expressionAttributeValues = {};

    Object.keys(updates).forEach(key => {
      const placeholder = `#${key}`;
      updateExpression.push(`${placeholder} = :${key}`);
      expressionAttributeNames[placeholder] = key;
      expressionAttributeValues[`:${key}`] = updates[key];
    });

    const updateParams = {
      TableName: this.usersTable,
      Key: { id: user.id }, // Use the primary key (id)
      UpdateExpression: `SET ${updateExpression.join(', ')}`,
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
      ReturnValues: 'ALL_NEW' // Return the updated item
    };

    const updateResult = await this.documentClient.send(new UpdateCommand(updateParams));
    return { item: updateResult.Attributes };
  }

  async updatePassword (email, currentPassword, newPassword) {
    if (!email || !currentPassword || !newPassword) {
      throw new Error('Email, current password, and new password are required.');
    }

    // Step 1: Query the user by email
    const queryParams = {
      TableName: this.usersTable,
      IndexName: 'email-index', // Use the GSI for email
      KeyConditionExpression: '#email = :email',
      ExpressionAttributeNames: {
        '#email': 'email'
      },
      ExpressionAttributeValues: {
        ':email': email
      }
    };

    const userResult = await this.documentClient.send(new QueryCommand(queryParams));

    if (!userResult.Items || userResult.Items.length === 0) {
      throw new Error('User not found.');
    }

    const user = userResult.Items[0];

    const isPasswordCorrect = await bcrypt.compare(currentPassword, user.hashed_password);
    if (!isPasswordCorrect) {
      throw new Error('Current password is incorrect.');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const updateParams = {
      TableName: this.usersTable,
      Key: { id: user.id },
      UpdateExpression: 'SET hashed_password = :hashed_password',
      ExpressionAttributeValues: {
        ':hashed_password': hashedPassword
      },
      ConditionExpression: 'attribute_exists(id)',
      ReturnValues: 'ALL_NEW'
    };

    const updateResult = await this.documentClient.send(new UpdateCommand(updateParams));
    const updatedUser = updateResult.Attributes;
    delete updatedUser.hashed_password;
    return { item: updatedUser };
  }

  async deleteUser (id) {
    if (!id) throw new Error('User ID is required.');

    const params = {
      TableName: this.usersTable,
      Key: { id },
      ConditionExpression: 'attribute_exists(id)' // Ensure the user exists before deleting
    };

    return new Promise((resolve, reject) => {
      this.documentClient.send(new DeleteCommand(params))
        .then(() => {
          resolve({}); // Resolve with an empty object if successful
        })
        .catch(err => {
          if (err.name === 'ConditionalCheckFailedException') {
            return reject(new Error('User not found.'));
          }
          reject(err);
        });
    });
  }
}

module.exports = ErrsoleDynamoDB;
module.exports.default = ErrsoleDynamoDB;
