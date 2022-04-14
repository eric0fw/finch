defmodule Finch.Conn do
  @moduledoc false

  alias Mint.HTTP1
  alias Finch.Telemetry
  alias Finch.SSL
  alias Finch.Error

  def new(scheme, host, port, opts, parent) do
    %{
      scheme: scheme,
      host: host,
      port: port,
      opts: opts.conn_opts,
      parent: parent,
      last_checkin: System.monotonic_time(),
      max_idle_time: opts.conn_max_idle_time,
      mint: nil
    }
  end

  def connect(%{mint: mint} = conn) when not is_nil(mint) do
    meta = %{
      scheme: conn.scheme,
      host: conn.host,
      port: conn.port
    }

    Telemetry.event(:reused_connection, %{}, meta)
    {:ok, conn}
  end

  def connect(%{mint: nil} = conn) do
    meta = %{
      scheme: conn.scheme,
      host: conn.host,
      port: conn.port
    }

    start_time = Telemetry.start(:connect, meta)

    # We have to use Mint's top-level connect function or else proxying won't work. So we
    # force the connection to use http1 and call it in this roundabout way.
    conn_opts = Keyword.merge(conn.opts, mode: :passive, protocols: [:http1])

    case Mint.HTTP.connect(conn.scheme, conn.host, conn.port, conn_opts) do
      {:ok, mint} ->
        Telemetry.stop(:connect, start_time, meta)
        SSL.maybe_log_secrets(conn.scheme, conn_opts, mint)
        {:ok, %{conn | mint: mint}}

      {:error, error} ->
        meta = Map.put(meta, :error, error)
        Telemetry.stop(:connect, start_time, meta)
        {:error, conn, error}
    end
  end

  def transfer(conn, pid) do
    case HTTP1.controlling_process(conn.mint, pid) do
      # HTTP1.controlling_process causes a side-effect, but it doesn't actually
      # change the conn, so we can ignore the value returned above.
      {:ok, _} -> {:ok, conn}
      {:error, error} -> {:error, conn, error}
    end
  end

  def open?(%{mint: nil}), do: false
  def open?(%{mint: mint}), do: HTTP1.open?(mint)

  def idle_time(conn, unit \\ :native) do
    idle_time = System.monotonic_time() - conn.last_checkin

    System.convert_time_unit(idle_time, :native, unit)
  end

  def reusable?(%{max_idle_time: :infinity}, _idle_time), do: true
  def reusable?(%{max_idle_time: max_idle_time}, idle_time), do: idle_time <= max_idle_time

  def set_mode(conn, mode) when mode in [:active, :passive] do
    case HTTP1.set_mode(conn.mint, mode) do
      {:ok, mint} -> {:ok, %{conn | mint: mint}}
      _ -> {:error, "Connection is dead"}
    end
  end

  def discard(%{mint: nil}, _), do: :unknown

  def discard(conn, message) do
    case HTTP1.stream(conn.mint, message) do
      {:ok, mint, _responses} -> {:ok, %{conn | mint: mint}}
      {:error, _, reason, _} -> {:error, reason}
      :unknown -> :unknown
    end
  end

  def request(%{mint: nil} = conn, _, _, _, _, _, _), do: {:error, conn, "Could not connect"}

  def request(conn, req, acc, fun, receive_timeout, idle_time, max_body) do
    full_path = Finch.Request.request_path(req)

    metadata = %{request: req}

    extra_measurements = %{idle_time: idle_time}

    start_time = Telemetry.start(:send, metadata, extra_measurements)

    try do
      case HTTP1.request(conn.mint, req.method, full_path, req.headers, stream_or_body(req.body)) do
        {:ok, mint, ref} ->
          case maybe_stream_request_body(mint, ref, req.body, receive_timeout) do
            {:ok, mint} ->
              Telemetry.stop(:send, start_time, metadata, extra_measurements)
              start_time = Telemetry.start(:recv, metadata, extra_measurements)
              response = receive_response([], acc, fun, mint, ref, receive_timeout, max_body)
              handle_response(response, conn, metadata, start_time, extra_measurements)

            {:error, mint, error} ->
              handle_request_error(
                conn,
                mint,
                error,
                metadata,
                start_time,
                extra_measurements
              )
          end

        {:error, mint, error} ->
          handle_request_error(conn, mint, error, metadata, start_time, extra_measurements)
      end
    catch
      kind, error ->
        close(conn)
        Telemetry.exception(:recv, start_time, kind, error, __STACKTRACE__, metadata)
        :erlang.raise(kind, error, __STACKTRACE__)
    end
  end

  defp stream_or_body({:stream, _}), do: :stream
  defp stream_or_body(body), do: body

  defp handle_request_error(conn, mint, error, metadata, start_time, extra_measurements) do
    metadata = Map.put(metadata, :error, error)
    Telemetry.stop(:send, start_time, metadata, extra_measurements)
    {:error, %{conn | mint: mint}, error}
  end

  defp maybe_stream_request_body(mint, ref, {:stream, stream}, _timeout) do
    with {:ok, mint} <- stream_request_body(mint, ref, stream) do
      HTTP1.stream_request_body(mint, ref, :eof)
    end
  end

  defp maybe_stream_request_body(mint, _, _, _), do: {:ok, mint}

  defp stream_request_body(mint, ref, stream) do
    Enum.reduce_while(stream, {:ok, mint}, fn
      chunk, {:ok, mint} -> {:cont, HTTP1.stream_request_body(mint, ref, chunk)}
      _chunk, error -> {:halt, error}
    end)
  end

  def close(%{mint: nil} = conn), do: conn

  def close(conn) do
    {:ok, mint} = HTTP1.close(conn.mint)
    %{conn | mint: mint}
  end

  defp handle_response(response, conn, metadata, start_time, extra_measurements) do
    case response do
      {:ok, mint, {status, headers, _} = acc} ->
        metadata = Map.merge(metadata, %{status: status, headers: headers})
        Telemetry.stop(:recv, start_time, metadata, extra_measurements)
        {:ok, %{conn | mint: mint}, acc}

      {:error, _mint, error = :response_body_too_large} ->
        metadata = Map.put(metadata, :error, error)
        Telemetry.stop(:recv, start_time, metadata, extra_measurements)
        {:error, close(conn), Error.exception(error)}

      {:error, mint, error} ->
        metadata = Map.put(metadata, :error, error)
        Telemetry.stop(:recv, start_time, metadata, extra_measurements)
        {:error, %{conn | mint: mint}, error}
    end
  end

  defp receive_response(entries, acc, fun, mint, ref, timeout, max_body, body_sum \\ 0)

  defp receive_response([], acc, fun, mint, ref, timeout, max_body, body_sum) do
    case HTTP1.recv(mint, 0, timeout) do
      {:ok, mint, entries} ->
        receive_response(entries, acc, fun, mint, ref, timeout, max_body, body_sum)

      {:error, mint, error, _responses} ->
        {:error, mint, error}
    end
  end

  defp receive_response([entry | entries], acc, fun, mint, ref, timeout, max_body, body_sum) do
    case entry do
      {:status, ^ref, value} ->
        receive_response(
          entries,
          fun.({:status, value}, acc),
          fun,
          mint,
          ref,
          timeout,
          max_body,
          body_sum
        )

      {:headers, ^ref, value} ->
        with true <- is_integer(max_body),
             {_header_name, content_length_str} <- List.keyfind(value, "content-length", 0),
             {content_length, ""} = Integer.parse(content_length_str),
             true <- content_length > max_body do
          {:error, mint, :response_body_too_large}
        else
          _ ->
            receive_response(
              entries,
              fun.({:headers, value}, acc),
              fun,
              mint,
              ref,
              timeout,
              max_body,
              body_sum
            )
        end

      {:data, ^ref, value} ->
        body_sum = :erlang.iolist_size(value) + body_sum

        with true <- is_integer(max_body),
             true <- body_sum > max_body do
          {:error, mint, :response_body_too_large}
        else
          _ ->
            receive_response(
              entries,
              fun.({:data, value}, acc),
              fun,
              mint,
              ref,
              timeout,
              max_body,
              body_sum
            )
        end

      {:done, ^ref} ->
        {:ok, mint, acc}

      {:error, ^ref, error} ->
        {:error, mint, error}
    end
  end
end
