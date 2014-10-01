'use strict';

var posts = require('../controllers/posts');


// Article authorization helpers
var hasAuthorization = function(req, res, next) {
    if (!req.user.isAdmin && req.post.user.id !== req.user.id) {
        return res.send(401, 'User is not authorized');
    }
    next();
};


// The Package is past automatically as first parameter
module.exports = function(Posts, app, auth, database) {
    app.route('/posts')
        .get(posts.all)
        .post(auth.requiresLogin, posts.create);

    app.route('/searchposts')
        .post(auth.requiresLogin, posts.searchposts);

    app.route('/posts/:postId')
        .get(posts.show)
        .put(auth.requiresLogin, hasAuthorization, posts.update)
        .delete(auth.requiresLogin, hasAuthorization, posts.destroy);

    // Finish with setting up the postId param
    app.param('postId', posts.post);

    app.get('/posts/example/anyone', function(req, res, next) {
        res.send('Anyone can access this');
    });

    app.get('/posts/example/auth', auth.requiresLogin, function(req, res, next) {
        res.send('Only authenticated users can access this');
    });

    app.get('/posts/example/admin', auth.requiresAdmin, function(req, res, next) {
        res.send('Only users with Admin role can access this');
    });

    app.get('/posts/example/render', function(req, res, next) {
        Posts.render('index', {
            package: 'posts'
        }, function(err, html) {
            //Rendering a view from the Package server/views
            res.send(html);
        });
    });
};
