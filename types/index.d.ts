declare module 'errsole-dynamodb' {
    interface Log {
      id: string; 
      errsole_id?: number;
      timestamp: Date; 
      hostname: string;
      pid: number;
      source: string;
      level: string;
      message: string;
      meta?: string;
    }
  
    interface LogFilter {
      hostname?: string;
      pid?: number;
      level_json?: { source: string; level: string }[];
      sources?: string[];
      levels?: string[];
      lt_id?: string;
      gt_id?: string;
      lte_timestamp?: Date;
      gte_timestamp?: Date; 
      limit?: number;
      errsole_id?: number;
    }
  
    interface Config {
      id: string;
      key: string;
      value: string;
    }
  
    interface User {
      id: string;
      name: string;
      email: string;
      role: string;
    }
  
    interface Notification {
      id?: string;
      errsole_id: number;
      hostname: string;
      hashed_message: string;
      created_at?: string;
      updated_at?: string;
    }
  
    class ErrsoleDynamoDB {
      constructor(options: any);
  
      getConfig(key: string): Promise<{ item: Config }>;
      setConfig(key: string, value: string): Promise<{ item: Config }>;
      deleteConfig(key: string): Promise<void>;
  
      getHostnames(): Promise<{ items: string[] }>;
      postLogs(logEntries: Log[]): Promise<void>;
      getLogs(filters?: LogFilter): Promise<{ items: Log[] }>;
      searchLogs(searchTerms: string[], filters?: LogFilter): Promise<{ items: Log[], filters: LogFilter[] }>;
  
      getMeta(id: string): Promise<{ item: { id: string; meta: string } }>;
  
      createUser(user: { name: string; email: string; password: string; role: string }): Promise<{ item: User }>;
      verifyUser(email: string, password: string): Promise<{ item: User }>;
      getUserCount(): Promise<{ count: number }>;
      getAllUsers(): Promise<{ items: User[] }>;
      getUserByEmail(email: string): Promise<{ item: User }>;
      updateUserByEmail(email: string, updates: Partial<User>): Promise<{ item: User }>;
      updatePassword(email: string, currentPassword: string, newPassword: string): Promise<{ item: User }>;
      deleteUser(userId: string): Promise<void>;
      insertNotificationItem(notification: Notification): Promise<{ previousNotificationItem: Notification | null, todayNotificationCount: number }>;
    }
  
    export default ErrsoleDynamoDB;
  }
  