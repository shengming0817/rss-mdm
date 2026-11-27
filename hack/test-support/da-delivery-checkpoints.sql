-- Disposable probe records projection progress at each committed report acknowledgement.
CREATE TABLE public.t2_da_delivery_progress(tenant uuid NOT NULL, position bigint NOT NULL);
CREATE FUNCTION public.t2_da_delivery() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO public.t2_da_delivery_progress
 SELECT NEW.tenant_id, position FROM rss_projection.checkpoints
 WHERE tenant_id=NEW.tenant_id AND projection_id='da-inventory';
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.t2_da_delivery() FROM PUBLIC;
CREATE TRIGGER t2_delivery AFTER UPDATE OF delivery_pending ON rss_da.report_history
 FOR EACH ROW WHEN (OLD.delivery_pending AND NOT NEW.delivery_pending)
 EXECUTE FUNCTION public.t2_da_delivery();
