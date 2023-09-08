create table comments
(
    id         int auto_increment
        primary key,
    post_id    int                                 not null,
    user_id    int                                 not null,
    comment    text                                not null,
    created_at timestamp default CURRENT_TIMESTAMP not null
)
    charset = utf8mb4;

create table posts
(
    id         int auto_increment
        primary key,
    user_id    int                                 not null,
    mime       varchar(64)                         not null,
    imgdata    mediumblob                          not null,
    body       text                                not null,
    created_at timestamp default CURRENT_TIMESTAMP not null
)
    charset = utf8mb4;

create table users
(
    id           int auto_increment
        primary key,
    account_name varchar(64)                          not null,
    passhash     varchar(128)                         not null,
    authority    tinyint(1) default 0                 not null,
    del_flg      tinyint(1) default 0                 not null,
    created_at   timestamp  default CURRENT_TIMESTAMP not null,
    constraint account_name
        unique (account_name)
)
    charset = utf8mb4;

