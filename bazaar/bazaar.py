import click

from bazaar.commands.query import query


@click.group("command")
def cli():
    pass


cli.add_command(query)

if __name__ == "__main__":
    cli()
