package utils

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type DB struct {
	*sql.DB
}

func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	timeout := 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return db.DB.QueryContext(ctx, query, args)
}

func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	timeout := 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return db.DB.QueryRowContext(ctx, query, args)
}

func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	timeout := 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return db.DB.ExecContext(ctx, query, args)
}
