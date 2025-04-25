package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// 创建数据库连接
func connectToDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./login_system.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// 测试数据库连接
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return db, nil
}

// 创建所有表
func createTables(db *sql.DB) error {
	tableQueries := []string{
		`
        CREATE TABLE IF NOT EXISTS Users (
            user_id INTEGER PRIMARY KEY NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        `,
		`
        CREATE INDEX IF NOT EXISTS idx_users_username ON Users (username);
        `,
		`
        CREATE TABLE IF NOT EXISTS Roles (
            name TEXT PRIMARY KEY NOT NULL UNIQUE
        );
        `,
		`
        CREATE TABLE IF NOT EXISTS Permission (
            operation TEXT PRIMARY KEY NOT NULL UNIQUE
        );
        `,
		`
        CREATE TABLE IF NOT EXISTS Rela_user_role (
            user_id INTEGER NOT NULL,
            role_name TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES Users (user_id),
            FOREIGN KEY (role_name) REFERENCES Roles (name),
            PRIMARY KEY (user_id, role_name)
        );
        `,
		`
        CREATE TABLE IF NOT EXISTS Rela_role_permission (
            role_name TEXT NOT NULL,
            operation TEXT NOT NULL,
            FOREIGN KEY (role_name) REFERENCES Roles (name),
            FOREIGN KEY (operation) REFERENCES Permission (operation),
            PRIMARY KEY (role_name, operation)
        );
        `,
		`
        CREATE TABLE IF NOT EXISTS UserLogs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES Users (user_id)
        );
        `,
	}

	for _, query := range tableQueries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}
	return nil
}

// 插入用户并记录日志
func insertUser(db *sql.DB, userID int64, username, password string) error {
	// 对密码进行哈希处理
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		var result string
		if p := recover(); p != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("用户创建事务回滚: %v", p)
			panic(p)
		} else if err != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("用户创建事务回滚: %v", err)
		} else {
			err = tx.Commit()
			if err != nil {
				result = "失败"
				log.Printf("用户创建事务提交失败: %v", err)
			} else {
				result = "成功"
				log.Printf("用户创建事务提交成功")
			}
		}
		// 记录用户操作日志
		if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'CREATE_USER', ?)", userID, result); err != nil {
			log.Printf("Failed to insert user log: %v", err)
		}
	}()

	// 插入用户
	result, err := tx.Exec("INSERT INTO Users (user_id, username, password) VALUES (?, ?, ?)", userID, username, hashedPassword)
	if err != nil {
		log.Printf("Failed to insert user with ID %d: %v", userID, err)
		return fmt.Errorf("failed to insert user: %w", err)
	}
	// 获取插入的用户 ID
	insertedID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get inserted user ID for user %s: %v", username, err)
		return fmt.Errorf("failed to get inserted user ID: %w", err)
	}
	// 赋予用户普通用户角色
	if _, err := tx.Exec("INSERT INTO Rela_user_role (user_id, role_name) VALUES (?, 'common_user')", insertedID); err != nil {
		log.Printf("Failed to assign role to user ID %d: %v", insertedID, err)
		return fmt.Errorf("failed to assign role to user: %w", err)
	}
	return nil
}

// 用户创建
/*
func CreateUser(db *sql.DB, currentUserID int64, newUserID int64, username, password string) error {
    // 检查当前用户是否为高级管理员
    isAdmin, err := isAdmin(db, currentUserID)
    if err != nil {
        return err
    }
    if !isAdmin {
        return fmt.Errorf("only admin can create new users")
    }
    return insertUser(db, newUserID, username, password)
}
*/

// 用户删除
func DeleteUser(db *sql.DB, currentUserID, targetUserID int64) error {
	isAdmin, err := isAdmin(db, currentUserID)
	if err != nil {
		return err
	}
	if !isAdmin && currentUserID != targetUserID {
		return fmt.Errorf("you can only delete your own account")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		var result string
		if p := recover(); p != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("用户删除事务回滚: %v", p)
			panic(p)
		} else if err != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("用户删除事务回滚: %v", err)
		} else {
			err = tx.Commit()
			if err != nil {
				result = "失败"
				log.Printf("用户删除事务提交失败: %v", err)
			} else {
				result = "成功"
				log.Printf("用户删除事务提交成功")
			}
		}
		// 记录用户操作日志
		if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'DELETE_USER', ?)", currentUserID, result); err != nil {
			log.Printf("Failed to insert user log: %v", err)
		}
	}()

	// 删除用户
	if _, err := tx.Exec("DELETE FROM Users WHERE user_id =?", targetUserID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// 用户信息修改
func UpdateUserInfo(db *sql.DB, currentUserID, targetUserID int64, username, password string) error {
	isAdmin, err := isAdmin(db, currentUserID)
	if err != nil {
		return err
	}
	if !isAdmin && currentUserID != targetUserID {
		return fmt.Errorf("you can only update your own information")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		var result string
		if p := recover(); p != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("用户信息修改事务回滚: %v", p)
			panic(p)
		} else if err != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("用户信息修改事务回滚: %v", err)
		} else {
			err = tx.Commit()
			if err != nil {
				result = "失败"
				log.Printf("用户信息修改事务提交失败: %v", err)
			} else {
				result = "成功"
				log.Printf("用户信息修改事务提交成功")
			}
		}
		// 记录用户操作日志
		if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'UPDATE_USER_INFO', ?)", currentUserID, result); err != nil {
			log.Printf("Failed to insert user log: %v", err)
		}
	}()

	// 对密码进行哈希处理
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// 更新用户信息
	if _, err := tx.Exec("UPDATE Users SET username =?, password =? WHERE user_id =?", username, hashedPassword, targetUserID); err != nil {
		return fmt.Errorf("failed to update user info: %w", err)
	}
	return nil
}

// 角色权限修改
func ModifyRolePermissions(db *sql.DB, currentUserID int64, roleName string, operations []string) error {
	isAdmin, err := isAdmin(db, currentUserID)
	if err != nil {
		return err
	}
	if !isAdmin {
		return fmt.Errorf("only admin can modify role permissions")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		var result string
		if p := recover(); p != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("角色权限修改事务回滚: %v", p)
			panic(p)
		} else if err != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("角色权限修改事务回滚: %v", err)
		} else {
			err = tx.Commit()
			if err != nil {
				result = "失败"
				log.Printf("角色权限修改事务提交失败: %v", err)
			} else {
				result = "成功"
				log.Printf("角色权限修改事务提交成功")
			}
		}
		// 记录用户操作日志
		if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'MODIFY_ROLE_PERMISSIONS', ?)", currentUserID, result); err != nil {
			log.Printf("Failed to insert user log: %v", err)
		}
	}()

	// 先删除该角色的所有权限
	if _, err := tx.Exec("DELETE FROM Rela_role_permission WHERE role_name =?", roleName); err != nil {
		return fmt.Errorf("failed to delete existing role permissions: %w", err)
	}

	// 插入新的权限
	for _, operation := range operations {
		if _, err := tx.Exec("INSERT INTO Rela_role_permission (role_name, operation) VALUES (?,?)", roleName, operation); err != nil {
			return fmt.Errorf("failed to insert new role permission: %w", err)
		}
	}
	return nil
}

// 赋予用户角色
func AssignUserRole(db *sql.DB, currentUserID, targetUserID int64, roleName string) error {
	isAdmin, err := isAdmin(db, currentUserID)
	if err != nil {
		return err
	}
	if !isAdmin {
		return fmt.Errorf("only admin can assign user roles")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		var result string
		if p := recover(); p != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("赋予用户角色事务回滚: %v", p)
			panic(p)
		} else if err != nil {
			tx.Rollback()
			result = "失败"
			log.Printf("赋予用户角色事务回滚: %v", err)
		} else {
			err = tx.Commit()
			if err != nil {
				result = "失败"
				log.Printf("赋予用户角色事务提交失败: %v", err)
			} else {
				result = "成功"
				log.Printf("赋予用户角色事务提交成功")
			}
		}
		// 记录用户操作日志
		if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'ASSIGN_USER_ROLE', ?)", currentUserID, result); err != nil {
			log.Printf("Failed to insert user log: %v", err)
		}
	}()

	// 先删除该用户的所有角色
	if _, err := tx.Exec("DELETE FROM Rela_user_role WHERE user_id =?", targetUserID); err != nil {
		return fmt.Errorf("failed to delete existing user roles: %w", err)
	}

	// 赋予新角色
	if _, err := tx.Exec("INSERT INTO Rela_user_role (user_id, role_name) VALUES (?,?)", targetUserID, roleName); err != nil {
		return fmt.Errorf("failed to assign new user role: %w", err)
	}
	return nil
}

// 密码验证
func VerifyPassword(db *sql.DB, userID int64, password string) (bool, error) {
	var storedPassword string
	err := db.QueryRow("SELECT password FROM Users WHERE user_id =?", userID).Scan(&storedPassword)
	var result string
	if err != nil {
		if err == sql.ErrNoRows {
			result = "失败（用户不存在）"
			log.Printf("密码验证失败: 用户不存在")
			return false, nil
		}
		result = "失败（查询错误）"
		log.Printf("密码验证失败: 查询错误: %v", err)
		return false, fmt.Errorf("failed to verify password: %w", err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		result = "失败（密码不匹配）"
		log.Printf("密码验证失败: 密码不匹配")
		return false, nil
	}
	result = "成功"
	log.Printf("密码验证成功")
	// 记录用户操作日志
	if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'VERIFY_PASSWORD', ?)", userID, result); err != nil {
		log.Printf("Failed to insert user log: %v", err)
	}
	return true, nil
}

// 检查用户是否为高级管理员
func isAdmin(db *sql.DB, userID int64) (bool, error) {
	var count int
	err := db.QueryRow(`
        SELECT COUNT(*) 
        FROM Rela_user_role 
        JOIN Roles ON Rela_user_role.role_name = Roles.name 
        WHERE Rela_user_role.user_id =? AND Roles.name = 'admin'
    `, userID).Scan(&count)
	var result string
	if err != nil {
		result = "失败（查询错误）"
		log.Printf("检查管理员身份失败: 查询错误: %v", err)
		return false, fmt.Errorf("failed to check admin status: %w", err)
	}
	if count > 0 {
		result = "成功（是管理员）"
		log.Printf("检查管理员身份成功: 用户是管理员")
	} else {
		result = "成功（不是管理员）"
		log.Printf("检查管理员身份成功: 用户不是管理员")
	}
	// 记录用户操作日志
	if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'CHECK_ADMIN_STATUS', ?)", userID, result); err != nil {
		log.Printf("Failed to insert user log: %v", err)
	}
	return count > 0, nil
}

// 获取用户角色
func getUserRole(db *sql.DB, userID int64) (string, error) {
	var roleName string
	err := db.QueryRow("SELECT role_name FROM Rela_user_role WHERE user_id =?", userID).Scan(&roleName)
	var result string
	if err != nil {
		result = "失败（查询错误）"
		log.Printf("获取用户角色失败: 查询错误: %v", err)
		return "", fmt.Errorf("failed to get user role: %w", err)
	}
	result = "成功"
	log.Printf("获取用户角色成功: 角色为 %s", roleName)
	// 记录用户操作日志
	if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'GET_USER_ROLE', ?)", userID, result); err != nil {
		log.Printf("Failed to insert user log: %v", err)
	}
	return roleName, nil
}

// 查询用户权限
func QueryUserPermissions(db *sql.DB, userID int64) ([]string, error) {
	var permissions []string
	rows, err := db.Query(`
        SELECT operation 
        FROM Rela_user_role 
        JOIN Rela_role_permission ON Rela_user_role.role_name = Rela_role_permission.role_name 
        WHERE Rela_user_role.user_id =?
    `, userID)
	var result string
	if err != nil {
		result = "失败（查询错误）"
		log.Printf("查询用户权限失败: 查询错误: %v", err)
		return nil, fmt.Errorf("failed to query user permissions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var operation string
		if err := rows.Scan(&operation); err != nil {
			result = "失败（扫描错误）"
			log.Printf("查询用户权限失败: 扫描错误: %v", err)
			return nil, fmt.Errorf("failed to scan user permissions: %w", err)
		}
		permissions = append(permissions, operation)
	}

	if err := rows.Err(); err != nil {
		result = "失败（迭代错误）"
		log.Printf("查询用户权限失败: 迭代错误: %v", err)
		return nil, fmt.Errorf("error iterating over user permissions: %w", err)
	}
	result = "成功"
	log.Printf("查询用户权限成功: 权限为 %v", permissions)
	// 记录用户操作日志
	if _, err := db.Exec("INSERT INTO UserLogs (user_id, action, result) VALUES (?, 'QUERY_USER_PERMISSIONS', ?)", userID, result); err != nil {
		log.Printf("Failed to insert user log: %v", err)
	}
	return permissions, nil
}

// 插入测试数据：测试用
func insertTestData(db *sql.DB) error {
	// 插入角色
	roles := []string{"admin", "common_user"}
	for _, role := range roles {
		if _, err := db.Exec("INSERT OR IGNORE INTO Roles (name) VALUES (?)", role); err != nil {
			return fmt.Errorf("failed to insert role: %w", err)
		}
	}

	// 插入权限
	permissions := []string{"read", "write", "delete"}
	for _, permission := range permissions {
		if _, err := db.Exec("INSERT OR IGNORE INTO Permission (operation) VALUES (?)", permission); err != nil {
			return fmt.Errorf("failed to insert permission: %w", err)
		}
	}

	// 插入用户
	if err := insertUser(db, 1, "admin", "admin123"); err != nil {
		return fmt.Errorf("failed to insert admin user: %w", err)
	}
	if err := insertUser(db, 2, "user1", "user123"); err != nil {
		return fmt.Errorf("failed to insert normal user: %w", err)
	}

	// 赋予 admin 角色权限
	adminPermissions := []string{"read", "write", "delete"}
	if err := ModifyRolePermissions(db, 1, "admin", adminPermissions); err != nil {
		return fmt.Errorf("failed to assign permissions to admin role: %w", err)
	}

	// 赋予 admin 用户 admin 角色
	if err := AssignUserRole(db, 1, 1, "admin"); err != nil {
		return fmt.Errorf("failed to assign admin role to admin user: %w", err)
	}

	return nil
}

func main() {
	// 连接到数据库
	db, err := connectToDatabase()
	if err != nil {
		log.Printf("Error connecting to database: %v", err)
		return
	}
	defer db.Close()

	// 创建表
	if err := createTables(db); err != nil {
		log.Printf("Error creating tables: %v", err)
		return
	}

	/*下面操作用于测试数据库操作，注释掉
	// 插入测试数据
	if err := insertTestData(db); err != nil {
		log.Printf("Error inserting test data: %v", err)
		return
	}

	// 示例：删除用户
	if err := DeleteUser(db, 1, 2); err != nil {
		log.Printf("Error deleting user: %v", err)
	}

	// 示例：修改用户信息
	if err := UpdateUserInfo(db, 1, 1, "updated_admin", "updated_admin123"); err != nil {
		log.Printf("Error updating user info: %v", err)
	}

	// 示例：角色权限修改
	newAdminPermissions := []string{"read", "write"}
	if err := ModifyRolePermissions(db, 1, "admin", newAdminPermissions); err != nil {
		log.Printf("Error modifying role permissions: %v", err)
	}

	// 示例：赋予用户角色
	if err := AssignUserRole(db, 1, 2, "admin"); err != nil {
		log.Printf("Error assigning user role: %v", err)
	}

	// 示例：密码验证
	valid, err := VerifyPassword(db, 1, "updated_admin123")
	if err != nil {
		log.Printf("Error verifying password: %v", err)
	}
	fmt.Printf("Password verification result: %v\n", valid)

	// 示例：查询用户权限
	permissions, err := QueryUserPermissions(db, 1)
	if err != nil {
		log.Printf("Error querying user permissions: %v", err)
	} else {
		fmt.Printf("User permissions: %v\n", permissions)
	}

	fmt.Println("Database operations complete.")
	*/
}
