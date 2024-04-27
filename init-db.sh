#!/bin/bash

# Wait for CockroachDB to start
sleep 5

# Create the database
cockroach sql --insecure -e 'CREATE DATABASE IF NOT EXISTS userstore;'
