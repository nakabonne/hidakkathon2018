alter table iines add index (article_id);

alter table articles add index (author_id);

alter table article_relate_tags add index (tag_id);
