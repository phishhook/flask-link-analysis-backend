import unittest
from app import app
import matplotlib.pyplot as plt
import numpy as np

class TestYourApp(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.percentages = []
        self.link_num = 0

    def test_index(self):
        # Open the text file and read the domains
        with open('phishing-domains-NEW-today.txt', 'r') as file:
            for line in file:
                domain = line.strip()
                response = self.app.post("/", query_string={"url": domain})
                data = response.data.decode('utf-8')

                if data == "N/A" :
                    print("hi")
                elif float(data.rstrip('%')) > 60:
                    print(domain)

                # Assuming 'data' contains the percentage value, extract and store it
                # Adjust this part based on the actual structure of 'data'

                self.percentages.append(data)
                

                self.link_num += 1
                print(self.link_num)

        # Plotting the bar graph after processing all domains
        self.plot_bar_graph()

    def plot_bar_graph(self):
        # Convert percentages to float
        float_percentages = [np.nan if percentage == "N/A" else float(percentage[:-1]) for percentage in self.percentages]

        # Count the occurrences of each unique percentage value
        unique_percentages, counts = np.unique(float_percentages, return_counts=True)

        # Sort unique_percentages based on float values
        sorted_indices = np.argsort(unique_percentages)
        unique_percentages = unique_percentages[sorted_indices]
        counts = counts[sorted_indices]

        # Set figure size to accommodate longer x-axis labels
        plt.figure(figsize=(25, 6))

        # Plotting the bar graph with sorted labels
        plt.bar([f"{percent:.2f}%" for percent in unique_percentages], counts, width=0.5, align='center')

        # Adding labels and title
        plt.xlabel('Percentage Safe')
        plt.ylabel('Frequency')
        plt.title('Model 1: Distribution of Percentage Values for Known Malicious Sites')

        # Display the plot
        plt.show()


if __name__ == '__main__':
    unittest.main()
