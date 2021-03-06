'use strict';
const apm = require('elastic-apm-node')
const cache = require('memory-cache');

const OPERATION_CREATE = 'CREATE',
      OPERATION_DELETE = 'DELETE';

class TodoController {
    constructor({redisClient, logChannel}) {
        this._redisClient = redisClient;
        this._logChannel = logChannel;
    }

    // TODO: these methods are not concurrent-safe
    list (req, res) {
        const data = this._getTodoData(req.user.username)
        res.json(data.items)
    }

    create (req, res) {
        // TODO: must be transactional and protected for concurrent access, but
        // the purpose of the whole example app it's enough
        var span = apm.startSpan('creating-item')
        const data = this._getTodoData(req.user.username)
        const todo = {
            content: req.body.content,
            id: data.lastInsertedID
        }
        data.items[data.lastInsertedID] = todo
        data.lastInsertedID++
        this._setTodoData(req.user.username, data)
        if (span) span.end()
        this._logOperation(OPERATION_CREATE, req.user.username, todo.id)
        res.json(todo)
    }

    delete (req, res) {
        const data = this._getTodoData(req.user.username)
        const id = req.params.taskId
        var span = apm.startSpan('deleting-item')
        delete data.items[id]
        this._setTodoData(req.user.username, data)
        if (span) span.end()
        this._logOperation(OPERATION_DELETE, req.user.username, id)
        res.status(204)
        res.send()
    }

    _logOperation(opName, username, todoId) {
      var span = apm.startSpan('logging-operation')
      this._redisClient.publish(
        this._logChannel,
        JSON.stringify({
          opName,
          username,
          todoId,
          spanTransaction: span.transaction
        }),
        function(err) {
          if (span) span.end()
          if (err) {
            apm.captureError(err)
          }
        }
      )
    }

    _getTodoData (userID) {
        var span = apm.startSpan('getting-items')
        var data = cache.get(userID)
        if (data == null) {
            data = {
                items: {
                    '1': {
                        id: 1,
                        content: "Create new todo",
                    },
                    '2': {
                        id: 2,
                        content: "Update me",
                    },
                    '3': {
                        id: 3,
                        content: "Delete example ones",
                    }
                },
                lastInsertedID: 3
            }

            this._setTodoData(userID, data)
            if (span) span.end()
            this._logOperation('GET', userID, data)
        }
        return data
    }

    _setTodoData (userID, data) {
        var span = apm.startSpan('setting-items')
        cache.put(userID, data)
        if (span) span.end()
        this._logOperation('SET', userID, data)
    }
}

module.exports = TodoController

