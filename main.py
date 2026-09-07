from input.handler import create_analysis_request


def main():
    print("\n========================================")
    print("       FSICOM AI LOG ANALYZER")
    print("========================================\n")

    repo_path = input("Enter repository path: ").strip()

    defect_description = input(
        "\nEnter defect description:\n"
    ).strip()

    blf_path = input("\nEnter BLF file path: ").strip()

    try:
        request = create_analysis_request(
            repo_path=repo_path,
            defect_description=defect_description,
            blf_path=blf_path
        )

        print("\n----------------------------------------")
        print("Input validation successful!")
        print("----------------------------------------")

        print(f"\nRepository : {request.repo_path}")
        print(f"Defect     : {request.defect_description}")
        print(f"BLF        : {request.blf_path}")

        print("\nReady to start analysis.")

    except ValueError as error:
        print(f"\nInput Error: {error}")


if __name__ == "__main__":
    main()