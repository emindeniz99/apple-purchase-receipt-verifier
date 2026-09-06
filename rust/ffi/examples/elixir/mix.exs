defmodule Mix.Tasks.Compile.AprvNif do
  @moduledoc false

  # A four-line Mix compiler instead of the elixir_make package. The example
  # is meant to be readable and runnable with nothing fetched, so it carries
  # no Hex dependencies at all; running `make` and re-linking priv/ is the
  # whole of what elixir_make would have done here.

  use Mix.Task.Compiler

  @impl Mix.Task.Compiler
  def run(_args) do
    # -s so a no-op rebuild says nothing; a compiler warning still reaches
    # stderr and is printed below.
    {output, status} = System.cmd("make", ["-s"], stderr_to_stdout: true)
    if output != "", do: IO.write(output)
    if status != 0, do: Mix.raise("make failed with status #{status}")

    # priv/ is symlinked into _build; it has to exist and be current before
    # the application can find the shared object at load time.
    Mix.Project.build_structure()
    :ok
  end

  @impl Mix.Task.Compiler
  def clean do
    System.cmd("make", ["clean"], stderr_to_stdout: true)
    :ok
  end
end

defmodule AppleReceiptExample.MixProject do
  use Mix.Project

  def project do
    [
      app: :apple_receipt_example,
      version: "0.0.0",
      elixir: "~> 1.18",
      compilers: [:aprv_nif] ++ Mix.compilers(),
      start_permanent: false,
      elixirc_options: [warnings_as_errors: true],
      deps: []
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end
end
