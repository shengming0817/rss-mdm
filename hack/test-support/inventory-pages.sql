-- Disposable verifier, installed only while observing a running product worker.
CREATE TABLE public.t2_inventory_pages(
 tenant uuid NOT NULL, projection text NOT NULL, position bigint NOT NULL, writer xid8 NOT NULL
);
CREATE FUNCTION public.t2_inventory_page() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO public.t2_inventory_pages VALUES (NEW.tenant_id,NEW.projection_id,NEW.position,pg_current_xact_id());
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.t2_inventory_page() FROM PUBLIC;
CREATE TRIGGER t2_inventory_page AFTER UPDATE OF position ON rss_projection.checkpoints
 FOR EACH ROW WHEN(NEW.position IS DISTINCT FROM OLD.position) EXECUTE FUNCTION public.t2_inventory_page();
